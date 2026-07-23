pluginManagement {
    includeBuild("../BuildGates")
}

rootProject.name = "vv"

include("vv_spring")

includeBuild("../BuildGates")
includeBuild("../ValueDescriptors")
