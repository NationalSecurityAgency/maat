/*
 * Copyright 2020 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "maat-basetypes.h"

int register_types(void)
{
    int ret_val;
    dlog(4, "Registering all known address spaces\n");
    if(( ret_val = register_address_spaces()) != 0) {
        dlog(0, "Registering address spaces failed with code %d\n", ret_val);
        return ret_val;
    }
    dlog(4, "Registering all known target types\n");
    if((ret_val = register_target_types()) != 0) {
        dlog(0, "Registering target types failed with code %d\n", ret_val);
        return ret_val;
    }
    dlog(4, "Registering all known measurement types\n");
    if((ret_val = register_measurement_types()) != 0) {
        dlog(0, "Registering measurement types failed with code %d\n", ret_val);
        return ret_val;
    }
    return 0;
}
