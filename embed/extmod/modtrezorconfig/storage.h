/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <stddef.h>
#include "secbool.h"
#include "py/obj.h"

void storage_init(void);
void storage_wipe(void);
secbool storage_unlock(const uint32_t pin, mp_obj_t callback);
secbool storage_has_pin(void);
uint32_t storage_pin_wait_time(void);
secbool storage_change_pin(const uint32_t pin, const uint32_t newpin, mp_obj_t callback);
secbool storage_get(uint16_t key, const void **val, uint16_t *len);
secbool storage_set(uint16_t key, const void *val, uint16_t len);
