





#############################################
#            Install                        #
#############################################


#configure_file("${CMAKE_CURRENT_LIST_DIR}/libOTeDepHelper.cmake" "libOTeDepHelper.cmake" )

# make cache variables for install destinations
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)


# generate the config file that is includes the exports
configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/libOTeConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libOTe
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

if(NOT DEFINED libOTe_VERSION_MAJOR)
    message("\n\n\n\n warning, libOTe_VERSION_MAJOR not defined ${libOTe_VERSION_MAJOR}")
endif()

set_property(TARGET libOTe PROPERTY VERSION ${libOTe_VERSION})

# generate the version file for the config file
configure_file(
  "${CMAKE_CURRENT_LIST_DIR}/buildOptions.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/buildOptions.cmake")
configure_file(
  "${CMAKE_CURRENT_LIST_DIR}/ConfigVersion.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/libOTeConfigVersion.cmake" COPYONLY)
#write_basic_package_version_file(
#  "${CMAKE_CURRENT_BINARY_DIR}/libOTeConfigVersion.cmake"
#  VERSION "${libOTe_VERSION_MAJOR}.${libOTe_VERSION_MINOR}.${libOTe_VERSION_PATCH}"
#  COMPATIBILITY AnyNewerVersion
#)

configure_file("${CMAKE_CURRENT_LIST_DIR}/libOTeDepHelper.cmake" "libOTeDepHelper.cmake" COPYONLY)
configure_file("${CMAKE_CURRENT_LIST_DIR}/libOTePreamble.cmake" "libOTePreamble.cmake" COPYONLY)

# install the configuration file
install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/libOTeConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/buildOptions.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/libOTeConfigVersion.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/libOTeDepHelper.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/libOTePreamble.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libOTe
)

set(exportLibs 
    "libOTe;libOTe_Tests;")

if(ENABLE_MR_KYBER)
    set(exportLibs "${exportLibs}KyberOT;")
    
    # install headers
    install(
        DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../KyberOT/ 
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/KyberOT 
        FILES_MATCHING PATTERN "*.h")
endif()

if(ENABLE_SIMPLESTOT_ASM)
    set(exportLibs "${exportLibs}SimplestOT;")
    # install headers
    install(
        DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../SimplestOT/ 
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/SimplestOT 
        FILES_MATCHING PATTERN "*.h")
endif()

# install library
install(
    TARGETS ${exportLibs}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    EXPORT libOTeTargets)

# install headers
install(
    DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../libOTe/ 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libOTe 
    FILES_MATCHING PATTERN "*.h")

#install config header
install(
    DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/libOTe"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/"
    FILES_MATCHING PATTERN "*.h")

# install test headers
install(
    DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../libOTe_Tests/ 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libOTe_Tests 
    FILES_MATCHING PATTERN "*.h")

# install config
install(EXPORT libOTeTargets
  FILE libOTeTargets.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libOTe
       NAMESPACE oc::
)
 export(EXPORT libOTeTargets
       FILE "${CMAKE_CURRENT_BINARY_DIR}/libOTeTargets.cmake"
       NAMESPACE oc::
)