from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.files import copy
from pathlib import Path


class WorkerHandoffRecipe(ConanFile):
    name = "worker-handoff"
    version = "0.7.0"
    package_type = "header-library"
    license = "MIT"
    url = "https://github.com/thisistuhinsen/workerOS"
    description = "Read a Linux file descriptor inherited from workerOS"
    settings = "os"
    no_copy_source = True
    exports_sources = "include/*", "LICENSE"

    def validate(self):
        if self.settings.os != "Linux":
            raise ConanInvalidConfiguration("worker-handoff inherited descriptors require Linux")

    def package_id(self):
        self.info.clear()

    def package(self):
        source = Path(self.source_folder)
        package = Path(self.package_folder)
        copy(self, "*.h", str(source / "include"), str(package / "include"))
        copy(self, "LICENSE", str(source), str(package / "licenses"))

    def package_info(self):
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []
        self.cpp_info.set_property("cmake_file_name", "worker-handoff")
        self.cpp_info.set_property("cmake_target_name", "worker-handoff::worker-handoff")
