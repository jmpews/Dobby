#include "hookzz_internal.h"

#include "logging/logging.h"

#include "Interceptor.h"
#include "InterceptRouting.h"

#if 0
PUBLIC RetStatus zz_enable_arm_arm64_b_branch() {
  DLOG("%s", "[*] Enable Intercepter ARM/ARM64 B Branch\n");

  Interceptor *interceptor = Interceptor::SharedInstance();
  // TODO: replace with getter or setter
  // DEL interceptor->enable_arm_arm64_b_branch();

  return RS_SUCCESS;
}

PUBLIC RetStatus zz_disable_arm_arm64_b_branch() {
  DLOG("%s", "[*] Disable Intercepter ARM/ARM64 B Branch\n");

  Interceptor *interceptor = Interceptor::SharedInstance();
  // TODO: replace with getter or setter
  // DEL interceptor->disable_arm_arm64_b_branch();

  return RS_SUCCESS;
}

#endif