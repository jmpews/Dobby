# Check files list exist
function(check_files_exist CHECK_FILES)
    foreach(file ${CHECK_FILES})
        if(NOT EXISTS "${file}")
            message(FATAL_ERROR "${file} NOT EXISTS!")
        endif()
    endforeach()
endfunction(check_files_exist CHECK_FILES)

# Search suffix files
function(search_suffix_files suffix INPUT_VARIABLE OUTPUT_VARIABLE)
    set(TMP_FILES )
    foreach(file_path ${${INPUT_VARIABLE}})
        # message(STATUS "[*] searching *.${suffix} from ${file_path}")
        file(GLOB file ${file_path}/*.${suffix})
        set(TMP_FILES ${TMP_FILES} ${file})
    endforeach()
    set(${OUTPUT_VARIABLE} ${TMP_FILES} PARENT_SCOPE)
endfunction()
