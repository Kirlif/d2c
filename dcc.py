#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import re
from sys import setrecursionlimit
from json import load
from io import BytesIO
from zipfile import ZipFile
from os import cpu_count, listdir, makedirs, name, path, sep
from logging import basicConfig, getLogger, INFO
from androguard.core.analysis import analysis
from androguard.core.bytecodes import dvm
from dex2c.compiler import Dex2C
from dex2c.util import (
    JniLongName,
    get_method_triple,
    get_access_method,
    is_synthetic_method,
    is_native_method,
)
from subprocess import check_call, check_output, run, STDOUT
from random import choice
from string import ascii_letters, digits
from shutil import copy, move, make_archive, rmtree, copytree

APKEDITOR = "tools/APKEditor.jar"
SIGNJAR = "tools/apksigner.jar"
MANIFEST_EDITOR = "tools/manifest-editor.jar"
Logger = getLogger("dcc")
basicConfig(level=INFO)


class MethodFilter(object):
    def __init__(self, configure, vm, skip_synthetic_methods, allow_init_methods):
        self._compile_filters = []
        self._keep_filters = []
        self._compile_full_match = set()
        self.conflict_methods = set()
        self.native_methods = set()
        self.annotated_methods = set()
        self.skip_synthetic_methods = skip_synthetic_methods
        self.allow_init_methods = allow_init_methods
        self._load_filter_configure(configure)
        self._init_conflict_methods(vm)
        self._init_native_methods(vm)
        self._init_annotation_methods(vm)

    def _load_filter_configure(self, configure):
        if not path.exists(configure):
            return
        with open(configure) as fp:
            for line in fp:
                line = line.strip()
                if not line or line[0] == "#":
                    continue
                if line[0] == "!":
                    line = line[1:].strip()
                    self._keep_filters.append(re.compile(line))
                elif line[0] == "=":
                    line = line[1:].strip()
                    self._compile_full_match.add(line)
                else:
                    self._compile_filters.append(re.compile(line))

    def _init_conflict_methods(self, vm):
        all_methods = {}
        for m in vm.get_methods():
            method_triple = get_method_triple(m, return_type=False)
            if method_triple in all_methods:
                self.conflict_methods.add(m)
                self.conflict_methods.add(all_methods[method_triple])
            else:
                all_methods[method_triple] = m

    def _init_native_methods(self, vm):
        for m in vm.get_methods():
            cls_name, name, _ = get_method_triple(m)
            access = get_access_method(m.get_access_flags())
            if "native" in access:
                self.native_methods.add((cls_name, name))

    def _add_annotation_method(self, method):
        if not is_synthetic_method(method) and not is_native_method(method):
            self.annotated_methods.add(method)

    def _init_annotation_methods(self, vm):
        for c in vm.get_classes():
            adi_off = c.get_annotations_off()
            if adi_off == 0:
                continue
            adi = vm.CM.get_obj_by_offset(adi_off)
            annotated_class = False
            # ref:https://github.com/androguard/androguard/issues/175
            if adi.get_class_annotations_off() != 0:
                ann_set_item = vm.CM.get_obj_by_offset(adi.get_class_annotations_off())
                for aoffitem in ann_set_item.get_annotation_off_item():
                    annotation_item = vm.CM.get_obj_by_offset(
                        aoffitem.get_annotation_off()
                    )
                    encoded_annotation = annotation_item.get_annotation()
                    type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                    if type_desc.endswith("Dex2C;"):
                        annotated_class = True
                        for method in c.get_methods():
                            self._add_annotation_method(method)
                        break
            if not annotated_class:
                for mi in adi.get_method_annotations():
                    method = vm.get_method_by_idx(mi.get_method_idx())
                    ann_set_item = vm.CM.get_obj_by_offset(mi.get_annotations_off())
                    for aoffitem in ann_set_item.get_annotation_off_item():
                        annotation_item = vm.CM.get_obj_by_offset(
                            aoffitem.get_annotation_off()
                        )
                        encoded_annotation = annotation_item.get_annotation()
                        type_desc = vm.CM.get_type(encoded_annotation.get_type_idx())
                        if type_desc.endswith("Dex2C;"):
                            self._add_annotation_method(method)

    def should_compile(self, method):
        # don't compile functions that have same parameter but differ return type
        if method in self.conflict_methods:
            return False
        # synthetic method
        if is_synthetic_method(method) and self.skip_synthetic_methods:
            return False
        # native method
        if is_native_method(method):
            return False
        method_triple = get_method_triple(method)
        cls_name, name, _ = method_triple
        # Skip static constructor
        if name == "<clinit>":
            return False
        if name == "<init>" and not self.allow_init_methods:
            return False
        # Android VM may find the wrong method using short jni name
        # don't compile function if there is a same named native method
        if (cls_name, name) in self.native_methods:
            return False
        full_name = "".join(method_triple)
        for rule in self._keep_filters:
            if rule.search(full_name):
                return False
        if full_name in self._compile_full_match:
            return True
        if method in self.annotated_methods:
            return True
        for rule in self._compile_filters:
            if rule.search(full_name):
                return True
        return False


class APKEditor:
    def compile_apk(decompiled_dir):
        unsigned_apk = make_temp_file("-unsigned.apk")
        check_call(
            [
                "java",
                "-jar",
                APKEDITOR,
                "b",
                "-no-cache",
                "-f",
                "-i",
                decompiled_dir,
                "-o",
                unsigned_apk,
            ],
            stderr=STDOUT,
        )
        return unsigned_apk

    def compile_dex(decompiled_dir, api, output_dex):
        check_call(
            [
                "java",
                "-cp",
                APKEDITOR,
                "org.jf.smali.Main",
                "a",
                "-a",
                api,
                "-o",
                output_dex,
                decompiled_dir,
            ],
            stderr=STDOUT,
        )
        return output_dex

    def decompile_apk(apk):
        outdir = make_temp_dir("dcc-APKEditor-")
        check_call(
            [
                "java",
                "-jar",
                APKEDITOR,
                "d",
                "-f",
                "-t",
                "raw",
                "-i",
                apk,
                "-o",
                outdir,
            ],
            stderr=STDOUT,
        )
        return outdir

    def decompile_dex(dex, api):
        outdir = make_temp_dir("dcc-APKEditor-")
        check_call(
            [
                "java",
                "-cp",
                APKEDITOR,
                "org.jf.baksmali.Main",
                "d",
                "-a",
                api,
                "-o",
                outdir,
                dex,
            ],
            stderr=STDOUT,
        )
        return outdir

    def get_info(apk_file, flag):
        man = check_output(
            ["java", "-jar", APKEDITOR, "info", flag, "-i", apk_file],
            stderr=STDOUT,
        ).decode()
        return man.split('"')[1] if man else ""


class DCC:
    def __init__(self, args_, ndk_build_):
        self.input_file = args_["input"]
        self.out_file = args_["output"]
        self.is_apk, self.min_sdk = is_apk(self.input_file)
        self.is_dex, self.api = (False, -1) if self.is_apk else is_dex(self.input_file)
        self.obfus = args_["obfuscate"]
        self.dynamic_register = args_["dynamic_register"]
        self.skip_synthetic_methods = args_["skip_synthetic"]
        self.allow_init_methods = args_["allow_init"]
        self.ignore_app_lib_abis = args_["force_keep_libs"]
        self.do_compile = not args_["no_build"]
        self.filter_cfg = args_["filter"]
        self.custom_loader = args_["custom_loader"]
        self.force_custom_loader = args_["force_custom_loader"]
        self.lib_name = args_["lib_name"]
        self.project_dir = args_["source_dir"]
        self.source_archive = args_["project_archive"]
        self.ndk_build = ndk_build_
        self.dex_files = None
        self.compiled_methods = None
        self.method_prototypes = None

    def build_project(self):
        check_call(
            [self.ndk_build, "-j%d" % cpu_cnt(), "-C", self.project_dir], stderr=STDOUT
        )

    def copy_compiled_libs(self):
        compiled_libs_dir = path.join(self.project_dir, "libs")
        decompiled_libs_dir = path.join(self.decompiled_dir, "root", "lib")
        if not path.exists(compiled_libs_dir):
            return
        if self.is_dex:
            copytree(compiled_libs_dir, path.join(self.dex_dir, "lib"))
            return
        if not path.exists(decompiled_libs_dir):
            copytree(compiled_libs_dir, decompiled_libs_dir)
            return
        for abi in listdir(decompiled_libs_dir):
            dst = path.join(decompiled_libs_dir, abi)
            src = path.join(compiled_libs_dir, abi)
            if not path.exists(src) and abi == "armeabi":
                src = path.join(compiled_libs_dir, "armeabi-v7a")
                Logger.warning(" Use armeabi-v7a for armeabi")
            if not path.exists(src):
                if self.ignore_app_lib_abis:
                    continue
                else:
                    raise Exception("ABI %s is not supported!" % abi)
            libnc = path.join(src, "lib" + self.lib_name + ".so")
            copy(libnc, dst)

    def native_class_methods(self, smali_path):
        def next_line():
            return fp.readline()

        def handle_annotanion():
            while True:
                line = next_line()
                if not line:
                    break
                s = line.strip()
                code_lines.append(line)
                if s == ".end annotation":
                    break
                else:
                    continue

        def handle_method_body():
            while True:
                line = next_line()
                if not line:
                    break
                s = line.strip()
                if s == ".end method":
                    break
                elif s.startswith(".annotation runtime") and s.find("Dex2C") < 0:
                    code_lines.append(line)
                    handle_annotanion()
                else:
                    continue

        code_lines = []
        class_name = ""
        with open(smali_path, "r") as fp:
            while True:
                line = next_line()
                if not line:
                    break
                code_lines.append(line)
                line = line.strip()
                if line.startswith(".class"):
                    class_name = line.split(" ")[-1]
                elif line.startswith(".method"):
                    current_method = line.split(" ")[-1]
                    param = current_method.find("(")
                    name, proto = current_method[:param], current_method[param:]
                    if (class_name, name, proto) in self.compiled_methods:
                        if line.find(" native ") < 0:
                            code_lines[-1] = code_lines[-1].replace(
                                current_method, "native " + current_method
                            )
                        handle_method_body()
                        code_lines.append(".end method\n")
        with open(smali_path, "w") as fp:
            fp.writelines(code_lines)

    def native_compiled_dexes(self):
        Logger.info(" Editing smali files")
        todo = []
        if self.is_apk:
            classes_output = list(
                filter(
                    lambda x: x.find("classes") >= 0,
                    listdir(path.join(self.decompiled_dir, "smali")),
                )
            )
            for classes in classes_output:
                for method_triple in self.compiled_methods.keys():
                    cls_name, name, proto = method_triple
                    cls_name = cls_name[1:-1]  # strip L;
                    smali_path = (
                        path.join(
                            path.join(self.decompiled_dir, "smali"), classes, cls_name
                        )
                        + ".smali"
                    )
                    if path.exists(smali_path):
                        todo.append(smali_path)
        else:
            for method_triple in self.compiled_methods.keys():
                cls_name, name, proto = method_triple
                cls_name = cls_name[1:-1]  # strip L;
                smali_path = path.join(self.decompiled_dir, cls_name) + ".smali"
                if path.exists(smali_path):
                    todo.append(smali_path)
        for smali_path in todo:
            self.native_class_methods(smali_path)

    def write_compiled_methods(self):
        source_dir = path.join(self.project_dir, "jni", "nc")
        if not path.exists(source_dir):
            makedirs(source_dir)
        for method_triple, code in self.compiled_methods.items():
            full_name = JniLongName(*method_triple)
            filepath = path.join(source_dir, full_name) + ".cpp"
            if path.exists(filepath):
                Logger.warning(" Overwrite file %s %s" % (filepath, method_triple))
            try:
                with open(filepath, "w", encoding="utf-8") as fp:
                    fp.write('#include "Dex2C.h"\n' + code)
            except Exception as e:
                print(f"{str(e)}\n")
        with open(path.join(source_dir, "compiled_methods.txt"), "w") as fp:
            fp.write("\n".join(list(map("".join, self.compiled_methods.keys()))))

    def archive_compiled_code(self):
        outfile = make_temp_file("-dcc")
        outfile = make_archive(outfile, "zip", self.project_dir)
        return outfile

    def compile_dex(self):
        Logger.info(" Converting...")
        compiled_method_code, native_method_prototype, errors = None, None, None
        dex_analysis = analysis.Analysis()
        native_method_prototype = {}
        compiled_method_code = {}
        errors = []
        for dex in self.dex_files:
            dex_analysis.add(dex)
        for dex in self.dex_files:
            method_filter = MethodFilter(
                self.filter_cfg,
                dex,
                self.skip_synthetic_methods,
                self.allow_init_methods,
            )
            compiler = Dex2C(dex, dex_analysis, self.obfus, self.dynamic_register)
            for m in dex.get_methods():
                method_triple = get_method_triple(m)
                jni_longname = JniLongName(*method_triple)
                full_name = "".join(method_triple)
                if len(jni_longname) > 220:
                    Logger.debug(
                        " Name to long %s(> 220) %s" % (jni_longname, full_name)
                    )
                    continue
                if method_filter.should_compile(m):
                    try:
                        code = compiler.get_source_method(m)
                    except Exception as e:
                        Logger.warning(
                            " compile method failed:%s (%s)" % (full_name, str(e)),
                            exc_info=True,
                        )
                        errors.append("%s:%s" % (full_name, str(e)))
                        continue
                    if code[0]:
                        compiled_method_code[method_triple] = code[0]
                        native_method_prototype[jni_longname] = code[1]
        return compiled_method_code, native_method_prototype, errors

    def get_classes_folders(self):
        folders = listdir(path.join(self.decompiled_dir, "smali"))
        folders = [
            path.join(self.decompiled_dir, "smali", folder)
            for folder in folders
            if path.isdir(path.join(self.decompiled_dir, "smali", folder))
            and folder.startswith("classes")
        ]
        return folders

    def get_application_class_file(self, classes_folders, application_name):
        if not application_name == "":
            file_name = application_name.replace(".", sep) + ".smali"
            for classes_folder in classes_folders:
                filePath = path.join(classes_folder, file_name)
                if path.exists(filePath):
                    return filePath
        return ""

    def get_dex_files_and_adjust_mk_files(self):
        supported_abis = {"armeabi-v7a", "arm64-v8a", "x86_64", "x86"}
        depreacated_abis = {"armeabi"}
        available_abis = set()
        pattern_abi, replacement_abi = "", ""
        Logger.info(" Reading dex files")
        if self.is_apk:
            with open(self.input_file, "rb") as f:
                zip_file = ZipFile(BytesIO(f.read()))
            dex_files = [
                dvm.DalvikVMFormat(zip_file.read(dex))
                for dex in filter(
                    lambda x: re.compile("classes(\\d*).dex").match(x),
                    zip_file.namelist(),
                )
            ]
            if not self.ignore_app_lib_abis:
                Logger.info(
                    " Adjusting Application.mk file using available abis from apk"
                )
                for file_name in zip_file.namelist():
                    if file_name.startswith("lib/"):
                        abi_name = file_name.split("/")[1].strip()
                        if len(file_name.split("/")) <= 2:
                            continue
                        if abi_name in supported_abis:
                            available_abis.add(abi_name)
                        elif abi_name in depreacated_abis:
                            Logger.warning(
                                " ABI 'armeabi' is depreacated, using 'armeabi-v7a' instead"
                            )
                            available_abis.add("armeabi-v7a")
                        else:
                            raise Exception(
                                f" ABI '{abi_name}' is unsupported, please remove it from apk or use flag --force-keep-libs and try again"
                            )
                if len(available_abis) == 0:
                    Logger.info(
                        " No lib abis found in apk, using the ones defined in Application.mk file"
                    )
                else:
                    pattern_abi = re.compile(r"APP_ABI *:=.*\n")
                    replacement_abi = f"APP_ABI := {' '.join(available_abis)}\n"
        else:
            with open(self.input_file, "rb") as f:
                dex = f.read()
            dex_files = [dvm.DalvikVMFormat(dex)]
            Logger.info(" using abis defined in Application.mk file")
        Logger.info(f" Setting APP_PLATFORM to {self.min_sdk}")
        pattern_platform = re.compile(r"APP_PLATFORM *:=.*\n")
        replacement_platform = f"APP_PLATFORM := {self.min_sdk}\n"
        with open("project/jni/Application.mk", "r+") as f:
            filedata = f.read()
            if pattern_abi:
                match = pattern_abi.search(filedata)
                filedata = filedata.replace(match.group(), replacement_abi)
            match = pattern_platform.search(filedata)
            filedata = filedata.replace(match.group(), replacement_platform)
            f.seek(0)
            f.write(filedata)
            f.truncate()
        pattern = re.compile(r"LOCAL_MODULE *:= *[\w\W]+?\n")
        replacement = f"LOCAL_MODULE := {self.lib_name}\n"
        if not pattern.match(replacement):
            Logger.error(" Invalid lib_name value in dcc.cfg")
            return
        with open("project/jni/Android.mk", "r+") as f:
            android_mk_file = f.read()
            match = pattern.search(android_mk_file)
            filedata = android_mk_file.replace(match.group(), replacement)
            f.seek(0)
            f.write(filedata)
            f.truncate()
        return dex_files

    def write_dummy_dynamic_register(self):
        source_dir = path.join(self.project_dir, "jni", "nc")
        if not path.exists(source_dir):
            makedirs(source_dir)
        filepath = path.join(source_dir, "DynamicRegister.cpp")
        with open(filepath, "w", encoding="utf-8") as fp:
            fp.write(
                '#include "DynamicRegister.h"\n\nconst char *dynamic_register_compile_methods(JNIEnv *env) { return nullptr; }'
            )

    def write_dynamic_register(self):
        source_dir = path.join(self.project_dir, "jni", "nc")
        if not path.exists(source_dir):
            makedirs(source_dir)
        export_list = {}
        # Make export list
        for method_triple in sorted(self.compiled_methods.keys()):
            full_name = JniLongName(*method_triple)
            if not full_name in self.method_prototypes:
                raise Exception(
                    "Method %s prototype info could not be found" % full_name
                )
            class_path = method_triple[0][1:-1].replace(".", "/")
            method_name = method_triple[1]
            method_signature = method_triple[2]
            method_native_name = full_name
            method_native_prototype = self.method_prototypes[full_name]
            if not class_path in export_list:
                export_list[class_path] = []  # methods
            export_list[class_path].append(
                (
                    method_name,
                    method_signature,
                    method_native_name,
                    method_native_prototype,
                )
            )
        if len(export_list) == 0:
            Logger.info("No export methods")
            return
        # Generate extern block and export block
        extern_block = []
        export_block = ["\njclass clazz;\n"]
        export_block_template = 'clazz = env->FindClass("%s");\nif (clazz == nullptr)\n    return "Class not found: %s";\n'
        export_block_template += (
            "const JNINativeMethod export_method_%d[] = {\n%s\n};\n"
        )
        export_block_template += "env->RegisterNatives(clazz, export_method_%d, %d);\n"
        export_block_template += "env->DeleteLocalRef(clazz);\n"
        for index, class_path in enumerate(sorted(export_list.keys())):
            methods = export_list[class_path]
            extern_block.append(
                "\n".join(["extern %s;" % method[3] for method in methods])
            )
            export_methods = ",\n".join(
                [
                    '{"%s", "%s", (void *)%s}' % (method[0], method[1], method[2])
                    for method in methods
                ]
            )
            export_block.append(
                export_block_template
                % (class_path, class_path, index, export_methods, index, len(methods))
            )
        export_block.append("return nullptr;\n")
        # Write DynamicRegister.cpp
        filepath = path.join(source_dir, "DynamicRegister.cpp")
        with open(filepath, "w", encoding="utf-8") as fp:
            fp.write('#include "DynamicRegister.h"\n\n')
            fp.write("\n".join(extern_block))
            fp.write("\n\nconst char *dynamic_register_compile_methods(JNIEnv *env) {")
            fp.write("\n".join(export_block))
            fp.write("}")

    def main(self):
        if not (self.is_apk or self.is_dex):
            Logger.error(f" {self.input_file} is not supported")
            return
        if not self.out_file:
            self.out_file = "output.apk" if self.is_apk else "output.zip"
        if self.custom_loader and self.custom_loader.rfind(".") == -1:
            Logger.error(
                " Custom Loader must have at least one package, such as \033[31mDemo.%s\033[0m\n",
                self.custom_loader,
            )
            return
        if self.is_dex:
            self.min_sdk = get_min_sdk_from_dex(self.api)
        self.dex_files = self.get_dex_files_and_adjust_mk_files()
        self.compiled_methods, self.method_prototypes, errors = self.compile_dex()
        if errors:
            Logger.warning(" ================================")
            Logger.warning("\n ".join(errors))
            Logger.warning(" ================================")
        if len(self.compiled_methods) == 0:
            Logger.info(" No methods compiled! Check your filter file.")
            return
        if self.project_dir:
            if not path.exists(self.project_dir):
                copytree("project", self.project_dir)
            self.write_compiled_methods()
        else:
            self.project_dir = make_temp_dir("dcc-project-")
            rmtree(self.project_dir)
            copytree("project", self.project_dir)
            self.write_compiled_methods()
        if not self.do_compile:
            move(self.archive_compiled_code(), self.source_archive)
        else:
            if self.dynamic_register:
                self.write_dynamic_register()
            else:
                self.write_dummy_dynamic_register()
            self.build_project()
        if self.is_dex:
            self.dex_dir = path.join(self.project_dir, "dex")
            if not path.exists(self.dex_dir):
                makedirs(self.dex_dir)
            Logger.info(f" Disassembling {self.input_file}")
            self.decompiled_dir = APKEditor.decompile_dex(self.input_file, self.api)
            self.native_compiled_dexes()
            self.copy_compiled_libs()
            Logger.info(" Assembling smali files")
            output_dex = path.join(self.dex_dir, self.input_file)
            APKEditor.compile_dex(self.decompiled_dir, self.api, output_dex)
            make_archive(path.splitext(self.out_file)[0], "zip", self.dex_dir)
            Logger.info(f" Completed: {self.out_file}")
        else:
            self.decompiled_dir = APKEditor.decompile_apk(self.input_file)
            self.native_compiled_dexes()
            self.copy_compiled_libs()
            application_class_name = APKEditor.get_info(self.input_file, "-app-class")
            classes_folders = self.get_classes_folders()
            app_class_file_path = self.get_application_class_file(
                classes_folders, application_class_name
            )
            has_app_class = application_class_name and app_class_file_path
            if not has_app_class or self.force_custom_loader:
                for classes_folder in classes_folders:
                    loader = path.join(
                        classes_folder, self.custom_loader.replace(".", sep) + ".smali"
                    )
                    if path.isfile(loader):
                        Logger.error(
                            f" Custom Loader \033[31m{self.custom_loader}\033[0m already exists in dex.\n"
                        )
                        return
                pattern = r'const-string v0, "[\w\W]+"'
                replacement = 'const-string v0, "' + self.lib_name + '"'
                loader_file_path = "loader/DccApplication.smali"
                temp_loader = make_temp_file("-Loader.smali")
                with open(loader_file_path, "r") as file:
                    filedata = file.read()
                filedata = re.sub(pattern, replacement, filedata)
                filedata = filedata.replace(
                    "Lamimo/dcc/DccApplication;",
                    "L" + self.custom_loader.replace(".", "/") + ";",
                )
                with open(temp_loader, "w") as file:
                    file.write(filedata)
                if not has_app_class:
                    Logger.info(
                        "\n Application class not found in the AndroidManifest.xml or doesn't exist in dex, adding \033[32m"
                        + self.custom_loader
                        + "\033[0m\n"
                    )
                    check_call(
                        [
                            "java",
                            "-jar",
                            MANIFEST_EDITOR,
                            path.join(self.decompiled_dir, "AndroidManifest.xml.bin"),
                            self.custom_loader,
                        ],
                        stderr=STDOUT,
                    )
                loader_dir = path.join(
                    classes_folders[-1],
                    self.custom_loader[: self.custom_loader.rfind(".")].replace(
                        ".", sep
                    ),
                )
                if not path.exists(loader_dir):
                    makedirs(loader_dir)
                copy(
                    temp_loader,
                    path.join(
                        classes_folders[-1],
                        self.custom_loader.replace(".", sep) + ".smali",
                    ),
                )
            if has_app_class:
                Logger.info(
                    "\n Application class from AndroidManifest.xml, \033[32m"
                    + application_class_name
                    + "\033[0m\n"
                )
                if self.force_custom_loader:
                    line_to_insert = f"    new-instance v0, L{self.custom_loader.replace('.', '/')};"
                else:
                    line_to_insert = (
                        f'    const-string v0, "{self.lib_name}"\n'
                        + "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
                    )
                code_block_to_append = f"""
                    .method static final constructor <clinit>()V
                        .locals 1
                    {line_to_insert}
                        return-void
                    .end method
                    """
                with open(app_class_file_path, "r") as file:
                    content = file.readlines()
                index = next(
                    (i for i, line in enumerate(content) if "<clinit>" in line), None
                )
                if index is not None:
                    locals_index = next(
                        (
                            i
                            for i, line in enumerate(content[index:])
                            if ".locals" in line or ".registers" in line
                        ),
                        None,
                    )
                    if locals_index is not None:
                        loc = re.compile("(    (?:\\.locals|\\.registers) )(\\d+)\n").search(content[index + locals_index])
                        if loc.group(2) == "0":
                            content[index + locals_index] = loc.group(1) + "1" + "\n"
                        content.insert(index + locals_index + 1, line_to_insert)
                    else:
                        Logger.error(
                            " Couldn't read <clinit> method in Application class"
                        )
                else:
                    content.append(code_block_to_append)
                with open(app_class_file_path, "w") as file:
                    file.writelines(content)
            unsigned_apk = APKEditor.compile_apk(self.decompiled_dir)
            sign(unsigned_apk, self.out_file, int(self.min_sdk))
            Logger.info(f" Completed: {self.out_file}")


def is_windows():
    return name == "nt"


def cpu_cnt():
    num_processes = cpu_count()
    if num_processes is None:
        num_processes = 2
    return num_processes


def create_tmp_directory():
    Logger.info(" Creating .tmp folder")
    if not path.exists(".tmp"):
        makedirs(".tmp")


def get_random_str(length=8):
    characters = ascii_letters + digits
    result = "".join(choice(characters) for _ in range(length))
    return result


def make_temp_dir(prefix="dcc"):
    random_str = get_random_str()
    tmp = path.join(".tmp", prefix + random_str)
    while path.exists(tmp) and path.isdir(tmp):
        random_str = get_random_str()
        tmp = path.join(".tmp", prefix + random_str)
    makedirs(tmp)
    return tmp


def make_temp_file(suffix=""):
    random_str = get_random_str()
    tmp = path.join(".tmp", random_str + suffix)
    while path.exists(tmp) and path.isfile(tmp):
        random_str = get_random_str()
        tmp = path.join(".tmp", random_str + suffix)
    open(tmp, "w")
    return tmp


def clean_tmp_directory():
    tmpdir = ".tmp"
    try:
        Logger.info(" Removing .tmp folder")
        rmtree(tmpdir)
    except OSError:
        run(["rd", "/s", "/q", tmpdir], shell=True)


def sign(unsigned_apk, signed_apk, min_sdk):
    Logger.info(f" Signing {unsigned_apk} -> {signed_apk}")
    with open("dcc.cfg") as fp:
        dcc_cfg = load(fp)
    signature = dcc_cfg["signature"]
    keystore = signature["keystore_path"]
    signature["v1_enabled"] = signature["v1_enabled"] and min_sdk < 24
    if (
        signature["v1_enabled"] is False
        and signature["v2_enabled"] is False
        and signature["v3_enabled"] is False
    ):
        Logger.warning(
            " At least one signing scheme should be enabled from v1, v2 & v3"
        )
        move_unsigned(unsigned_apk, signed_apk)
        return
    if not path.isfile(keystore):
        Logger.error(" KeyStore not found in defined path or not recognized as a file")
        move_unsigned(unsigned_apk, signed_apk)
        return
    command = ["java", "-jar", SIGNJAR, "sign", "--in", unsigned_apk, "--out", signed_apk,
               "--ks", keystore, "--ks-key-alias", signature["alias"],
               "--ks-pass", "pass:" + signature["keystore_pass"],
               "--key-pass", "pass:" + signature["store_pass"],
               "--v1-signing-enabled", "true" if signature["v1_enabled"] is True else "false",
               "--v2-signing-enabled", "true" if signature["v2_enabled"] is True else "false",
               "--v3-signing-enabled", "true" if signature["v3_enabled"] is True else "false",
               "--v4-signing-enabled", "false", "--verity-enabled", "false"]
    try:
        check_call(command, stderr=STDOUT)
    except Exception as ex:
        Logger.error(" Signing %s failed!" % unsigned_apk, exc_info=True)
        print(f"{str(ex)}")
        move_unsigned(unsigned_apk, signed_apk)


def move_unsigned(unsigned_apk, signed_apk):
    Logger.info(" Moving unsigned apk -> " + signed_apk)
    copy(unsigned_apk, signed_apk)


def is_apk(name_):
    try:
        apk = ZipFile(name_, mode="r")
        min_sdk = APKEditor.get_info(name_, "-min-sdk-version")
        return (
            all([f in apk.namelist() for f in ("AndroidManifest.xml", "classes.dex")]),
            min_sdk,
        )
    except:
        return False, None


def is_dex(name_):
    pat = re.compile(b"\x64\x65\x78\x0a\x30(\\d\\d)\x00")
    try:
        with open(name_, "rb") as f:
            magic = f.read()[:8]
        match = pat.match(magic)
        return True, get_api_from_dex(int(match.group(1).decode()))
    except:
        return False, None


def get_api_from_dex(ver):
    match ver:
        case 35:
            return "23"
        case 37:
            return "25"
        case 38:
            return "27"
        case 39:
            return "28"
        case 40:
            return "28"
        case _:
            raise Exception()

def get_min_sdk_from_dex(api):
    match api:
        case "23":
            return "21"
        case "25":
            return "24"
        case "27":
            return "26"
        case _:
            return "28"


def backup_jni_project_folder():
    Logger.info(" Backing up jni folder")
    src_path = path.join("project", "jni")
    dest_path = make_temp_dir("jni-")
    copytree(src_path, dest_path, dirs_exist_ok=True)
    return dest_path


def restore_jni_project_folder(src_path):
    Logger.info(" Restoring jni folder")
    dest_path = path.join("project", "jni")
    if path.exists(dest_path) and path.isdir(dest_path):
        rmtree(dest_path)
    copytree(src_path, dest_path)


setrecursionlimit(5000)
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Input apk/dex file path")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path, default: output.apk for APK, output.zip for DEX",
    )
    parser.add_argument(
        "-p", "--obfuscate", action="store_true", help="Obfuscate string constants."
    )
    parser.add_argument(
        "-d",
        "--dynamic-register",
        action="store_true",
        help="Export native methods using RegisterNatives.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="filter.txt",
        help="Method filters configuration file.",
    )
    parser.add_argument(
        "-c",
        "--custom-loader",
        default="amimo.dcc.DccApplication",
        help="Loader class, default: amimo.dcc.DccApplication",
    )
    parser.add_argument(
        "-r",
        "--force-custom-loader",
        action="store_true",
        help="Force use of custom loader",
    )
    parser.add_argument(
        "-s",
        "--skip-synthetic",
        action="store_true",
        help="Skip synthetic methods in all classes.",
    )
    parser.add_argument(
        "-a", "--allow-init", action="store_true", help="Do not skip init methods."
    )
    parser.add_argument(
        "-l",
        "--lib-name",
        default="stub",
        help="Lib name, default: stub",
    )
    parser.add_argument(
        "-b", "--no-build", action="store_true", help="Do not build the compiled code"
    )
    parser.add_argument(
        "-k",
        "--force-keep-libs",
        action="store_true",
        help="Forcefully keep the lib abis defined in Application.mk, regardless of the abis already available in the apk",
    )
    parser.add_argument(
        "-e",
        "--source-dir",
        default=None,
        help="The compiled cpp code output directory.",
    )
    parser.add_argument(
        "-z",
        "--project-archive",
        default="project-source.zip",
        help="Converted cpp code, compressed as zip output file. Works with --no-build",
    )
    args = vars(parser.parse_args())
    with open("dcc.cfg") as fp:
        dcc_cfg = load(fp)
    if "ndk_dir" in dcc_cfg and path.exists(dcc_cfg["ndk_dir"]):
        ndk_dir = dcc_cfg["ndk_dir"]
        if is_windows():
            ndk_build = path.join(ndk_dir, "ndk-build.cmd")
        else:
            ndk_build = path.join(ndk_dir, "ndk-build")
        if not path.exists(ndk_build):
            raise Exception("Invalid ndk_dir path, file not found at " + ndk_build)
    else:
        raise Exception("ndk_dir is not defined in dcc.cfg")
    for key in list(args.keys())[1:]:
        if key in dcc_cfg and dcc_cfg[key] and args[key] == parser.get_default(key):
            args[key] = dcc_cfg[key]
        if args[key] is not None:
            Logger.info(f"     {key} = {args[key]}")
    # Must be invoked first before invoking any other mehtod
    create_tmp_directory()
    # Backing up jni folder because modifications will be made in runtime
    backup_jni_folder_path = backup_jni_project_folder()
    try:
        DCC(args, ndk_build).main()
    except Exception as e:
        Logger.error(" Compile %s failed!" % args["input"], exc_info=True)
        print(f"{str(e)}")
    finally:
        restore_jni_project_folder(backup_jni_folder_path)
        clean_tmp_directory()
