#.rst:
# FindBotan3
# -----------
#
# Find the botan-3 library (Botan >= 3.13 required for GCM-SIV support).
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` targets:
#
# ``Botan3::Botan3``
#   The botan-3 library, if found.
#
# Result variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   BOTAN3_FOUND          - true if the headers and library were found
#   BOTAN3_INCLUDE_DIRS   - where to find headers
#   BOTAN3_LIBRARIES      - list of libraries to link
#   BOTAN3_VERSION        - library version that was found, if any

# use pkg-config to get the directories and then use these values
# in the find_path() and find_library() calls
find_package(PkgConfig QUIET)
pkg_check_modules(PC_BOTAN3 QUIET botan-3)

# find the headers
find_path(BOTAN3_INCLUDE_DIR
  NAMES botan/version.h
  HINTS
    ${PC_BOTAN3_INCLUDEDIR}
    ${PC_BOTAN3_INCLUDE_DIRS}
  PATH_SUFFIXES botan-3
)

# find the library
if(MSVC)
  find_library(BOTAN3_LIBRARY
    NAMES botan
    HINTS
      ${PC_BOTAN3_LIBDIR}
      ${PC_BOTAN3_LIBRARY_DIRS}
  )
else()
  find_library(BOTAN3_LIBRARY
    NAMES botan-3 libbotan-3
    HINTS
      ${PC_BOTAN3_LIBDIR}
      ${PC_BOTAN3_LIBRARY_DIRS}
  )
endif()

# determine the version
if(PC_BOTAN3_VERSION)
    set(BOTAN3_VERSION ${PC_BOTAN3_VERSION})
elseif(BOTAN3_INCLUDE_DIR AND EXISTS "${BOTAN3_INCLUDE_DIR}/botan/version.h")
    file(STRINGS "${BOTAN3_INCLUDE_DIR}/botan/version.h" botan3_version_str
      REGEX "^#define[\t ]+BOTAN_VERSION_[A-Z]+[\t ]+[0-9]+")

    string(REGEX REPLACE ".*#define[\t ]+BOTAN_VERSION_MAJOR[\t ]+([0-9]+).*"
           "\\1" _botan3_version_major "${botan3_version_str}")
    string(REGEX REPLACE ".*#define[\t ]+BOTAN_VERSION_MINOR[\t ]+([0-9]+).*"
           "\\1" _botan3_version_minor "${botan3_version_str}")
    string(REGEX REPLACE ".*#define[\t ]+BOTAN_VERSION_PATCH[\t ]+([0-9]+).*"
           "\\1" _botan3_version_patch "${botan3_version_str}")
    set(BOTAN3_VERSION "${_botan3_version_major}.${_botan3_version_minor}.${_botan3_version_patch}"
                       CACHE INTERNAL "The version of Botan which was detected")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Botan3
  REQUIRED_VARS BOTAN3_LIBRARY BOTAN3_INCLUDE_DIR
  VERSION_VAR BOTAN3_VERSION
)

if (BOTAN3_FOUND)
  set(BOTAN3_INCLUDE_DIRS ${BOTAN3_INCLUDE_DIR} ${PC_BOTAN3_INCLUDE_DIRS})
  set(BOTAN3_LIBRARIES ${BOTAN3_LIBRARY})
endif()

if (BOTAN3_FOUND AND NOT TARGET Botan3::Botan3)
  # create the new library target
  add_library(Botan3::Botan3 UNKNOWN IMPORTED)
  # set the required include dirs for the target
  if (BOTAN3_INCLUDE_DIRS)
    set_target_properties(Botan3::Botan3
      PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${BOTAN3_INCLUDE_DIRS}"
    )
  endif()
  # set the required libraries for the target
  if (EXISTS "${BOTAN3_LIBRARY}")
    set_target_properties(Botan3::Botan3
      PROPERTIES
        IMPORTED_LOCATION "${BOTAN3_LIBRARY}"
    )
  endif()
endif()

mark_as_advanced(BOTAN3_INCLUDE_DIR BOTAN3_LIBRARY)
