pluginManagement {
    includeBuild("../BuildGates")
}

rootProject.name = "vv"

include("vv_spring")
include("vv_boxedpath")
include("vv_httpcomponents")

includeBuild("../BuildGates")
includeBuild("../ValueDescriptors")
