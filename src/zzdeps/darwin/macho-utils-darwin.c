
#include <mach/task_info.h>
#include <mach-o/dyld_images.h>

#include "../common/debugbreak.h"
#include "macho-utils-darwin.h"
#include "../darwin/memory-utils-darwin.h"

// get dyld load address by task_info, TASK_DYLD_INFO
zpointer zz_macho_get_dyld_load_address_via_task(task_t task)
{
    // http://stackoverflow.com/questions/4309117/determining-programmatically-what-modules-are-loaded-in-another-process-os-x
    kern_return_t kr;
    task_flavor_t flavor = TASK_DYLD_INFO;
    task_dyld_info_data_t infoData;
    mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, flavor, (task_info_t)&infoData, &task_info_outCnt);
    if (kr != KERN_SUCCESS)
    {
        KR_ERROR(kr);
        return 0;
    }
    struct dyld_all_image_infos *allImageInfos =
        (struct dyld_all_image_infos *)infoData.all_image_info_addr;
    allImageInfos = (struct dyld_all_image_infos *)malloc(
        sizeof(struct dyld_all_image_infos));
    if (zz_vm_read_data_via_task(task, infoData.all_image_info_addr, allImageInfos,
                                 sizeof(struct dyld_all_image_infos)))
    {
        return (zpointer)(allImageInfos->dyldImageLoadAddress);
    }
    else
    {
        return NULL;
    }
}

task_t zz_darwin_get_task_via_pid(int pid)
{
    task_t t;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
    if (kr != KERN_SUCCESS)
    {
        KR_ERROR(kr);
        return 0;
    }
    return t;
}