cmake_minimum_required(VERSION 3.1)
project(remotecryptoiks)

if (WIN32)
    SET(VERSION_PRODUCTNAME_VALUE "remotecryptoiks")
    add_definitions(-DVERSION_PRODUCTNAME_VALUE="${VERSION_PRODUCTNAME_VALUE}")
endif()

file(GLOB_RECURSE SRCS *.cpp *.cc)
file(GLOB_RECURSE INCLUDE *.hpp)

add_library(
        remotecryptoiksunified
        SHARED
        ${SRCS}
        ${INCLUDE}
        ${resourcerc}
)

SET_TARGET_PROPERTIES(remotecryptoiksunified PROPERTIES VERSION ${LIBLOGICALACCESS_VERSION_STRING})
target_link_libraries(
        remotecryptoiksunified
        grpc grpc++ protobuf
        ${LIBLOGICALACCESS_LIBRARY}
)

install ( FILES ${INCLUDE} DESTINATION include/logicalaccess/plugins/iks )
install ( TARGETS remotecryptoiksunified  RUNTIME DESTINATION bin/${LIB_SUFFIX} ARCHIVE DESTINATION lib/${LIB_SUFFIX} LIBRARY DESTINATION lib/${LIB_SUFFIX} )
if (MSVC)
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION pdb/${LIB_SUFFIX} OPTIONAL)
endif()
