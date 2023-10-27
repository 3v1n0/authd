/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2023 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Author: Marco Trevisan (Treviño) <marco.trevisan@canonical.com>
 *
 */

#pragma once

#include "gdm-pam-extensions-common.h"

typedef struct {
        GdmPamExtensionMessage header;

        const char protocol_name[64];
        unsigned int version;
        char *value;
} GdmPamExtensionStringProtocol;

#define GDM_PAM_EXTENSION_PRIVATE_STRING "org.gnome.DisplayManager.UserVerifier.PrivateString"
#define GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE sizeof (GdmPamExtensionStringProtocol)

#define GDM_PAM_EXTENSION_PRIVATE_STRING_REQUEST_INIT(request, proto_name, proto_version, str_value) \
{ \
        GDM_PAM_EXTENSION_LOOK_UP_TYPE (GDM_PAM_EXTENSION_PRIVATE_STRING, &((request)->header.type)); \
        (request)->header.length = htobe32 (GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE); \
        strncpy ((char *)(request)->protocol_name, proto_name, sizeof ((request)->protocol_name) - 1); \
        (request)->version = proto_version; \
        (request)->value = (char *) str_value; \
}

#define GDM_PAM_EXTENSION_PRIVATE_STRING_RESPONSE_INIT(response, proto_name, proto_version) \
{ \
        GDM_PAM_EXTENSION_LOOK_UP_TYPE (GDM_PAM_EXTENSION_PRIVATE_STRING, &((response)->header.type)); \
        (response)->header.length = htobe32 (GDM_PAM_EXTENSION_PRIVATE_STRING_SIZE); \
        strncpy ((char *)(response)->protocol_name, proto_name, sizeof ((response)->protocol_name) - 1); \
        (response)->version = proto_version; \
        (response)->value = NULL; \
}
#define GDM_PAM_EXTENSION_REPLY_TO_PRIVATE_STRING_RESPONSE(reply) ((GdmPamExtensionStringProtocol *) (void *) reply->resp)
