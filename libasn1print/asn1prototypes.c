// Copyright 2020-present Open Networking Foundation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "asn1prototypes.h"

// get_version() parses version of the ASN.1 definition, if present, from the OID.
// It returns -1 if version was not found
int get_version(asn1p_oid_t *oid) {

	int vrsn = -1;

	for (int i = 0; i < oid->arcs_count; i++) {
		asn1p_oid_arc_t arc = oid->arcs[i];
		if (arc.name != NULL) { // sometimes it can occur, that there is only number, but not the name - it may break this algorithm
			if (strstr(arc.name, "version")) {
				vrsn = arc.number;
				break;
			}
		}
	}

	return vrsn;
}

// get_protobuf_package_name() adjusts module name to correspond to Go convention for the package naming
// (i.e., no dashes, no underscore, no mixed case)
char *
get_protobuf_package_name(char *name) {
	// Exclude underscores and dashes from the name of the package
	int j = 0;
	int i = 0;
	char *res = strdup(name);
	int origlen = strlen(name);
	while (j < origlen) {
		if (name[i] == '_' || name[i] == '-') {
			j--;
		} else {
			res[j] = name[i];
		}
		i++;
		j++;
	}

	return res;
}

char *
proto_remove_rel_path(char *path) {
	int count = 0;
	char *newStart = path;
	while (strstr(newStart, "../") != NULL) {
		if (strcmp(newStart, strstr(newStart, "../")) == 0) {
			newStart = newStart + 3;
			count++;
		}
	}
	while (count > 0) {
		if (strchr(newStart, '/') != NULL) {
			newStart = strchr(newStart, '/') + 1;
		}
		count--;
	}
	return newStart;
}

char *
proto_remove_whole_path(char *path) {
	return strrchr(path, '/') != NULL ? (strrchr(path, '/') + 1) : path;
}

proto_enum_t *
proto_create_enum(const char *name, const char *comment_fmt, char *src, const int line) {
	proto_enum_t *protoenum = malloc(sizeof(proto_enum_t));
	memset(protoenum, 0, sizeof(proto_enum_t));
	strcpy(protoenum->name, name);
	if (comment_fmt != NULL)
		sprintf(protoenum->comments, comment_fmt, proto_remove_whole_path(src), line);
	protoenum->def = calloc(0, sizeof(proto_enum_def_t *));
	protoenum->defs = 0;
	return protoenum;
}

proto_enum_def_t *
proto_create_enum_def(const char *name, const int index, const char *comment) {
	proto_enum_def_t *enumdef = malloc(sizeof(proto_enum_def_t));
	memset(enumdef, 0, sizeof(proto_enum_def_t));
	strcpy(enumdef->name, name);
	if (comment != NULL && strlen(comment) != 0) {
		strcpy(enumdef->comment, comment);
	}
	enumdef->index = index;
	return enumdef;
}

void
proto_enum_add_def(proto_enum_t *protoenum, proto_enum_def_t *def) {
	size_t existing_defs = protoenum->defs;
	protoenum->def = realloc(protoenum->def, (existing_defs + 1) * sizeof(proto_enum_def_t *));
	protoenum->def[existing_defs] = def;
	protoenum->defs = existing_defs + 1;
}

void
proto_enums_add_enum(proto_module_t *proto_module, proto_enum_t *protoenum) {
	size_t existing_count = proto_module->enums;
	proto_module->protoenum = realloc(proto_module->protoenum, (existing_count + 1) * sizeof(proto_enum_t *));
	proto_module->protoenum[existing_count] = protoenum;
	proto_module->enums = existing_count + 1;
}

proto_msg_oneof_t *
proto_create_msg_oneof(const char *name, const char *comment_fmt, char *src, const int line) {
	proto_msg_oneof_t *msg = malloc(sizeof(proto_msg_oneof_t));
	memset(msg, 0, sizeof(proto_msg_oneof_t));
	strcpy(msg->name, name);
	if (comment_fmt != NULL) {
		sprintf(msg->comments, comment_fmt, proto_remove_whole_path(src), line);
	}
	msg->entry = calloc(0, sizeof(proto_msg_def_t *));
	msg->entries = 0;
	return msg;
}

proto_msg_t *
proto_create_message(const char *name, int spec_index, int unique_idx, const char *comment_fmt, char *src,
					 const int line, const int isConstant) {
	proto_msg_t *msg = malloc(sizeof(proto_msg_t));
	memset(msg, 0, sizeof(proto_msg_t));
	if (spec_index > -1) {
		snprintf(msg->name, PROTO_NAME_CHARS, "%s%03d", name, unique_idx);
	} else {
		strcpy(msg->name, name);
	}
	if (comment_fmt != NULL) {
		sprintf(msg->comments, comment_fmt, proto_remove_whole_path(src), line);
	}
	msg->entry = calloc(0, sizeof(proto_msg_def_t *));
	msg->entries = 0;
	msg->nested = calloc(0, sizeof(proto_msg_t *));
	msg->nesteds = 0;
	msg->isConstant = isConstant;
	return msg;
}

proto_msg_def_t *
proto_create_msg_elem(const char *name, const char *type, const char *rules) {
	proto_msg_def_t *msgelem = malloc(sizeof(proto_msg_def_t));
	memset(msgelem, 0, sizeof(proto_msg_def_t));
	// ToDo - we don't know constraints yet..Have to be parsed correctly
	msgelem->tags.valueLB = -1;
	msgelem->tags.valueUB = -1;
	msgelem->tags.sizeLB = -1;
	msgelem->tags.sizeUB = -1;
	if (name) {
		strcpy(msgelem->name, name);
	} else {
		strcpy(msgelem->name, "value");
	}
	strcpy(msgelem->type, type);
	if (rules != NULL)
		strcpy(msgelem->rules, rules);
	return msgelem;
}

void
proto_msg_add_param(proto_msg_t *msg, proto_param_t *param) {
	size_t existing_params = msg->params;
	msg->param = realloc(msg->param, (existing_params + 1) * sizeof(proto_param_t *));
	msg->param[existing_params] = param;
	msg->params = existing_params + 1;
}

void
proto_msg_add_elem(proto_msg_t *msg, proto_msg_def_t *elem) {
	size_t existing_elems = msg->entries;
	msg->entry = realloc(msg->entry, (existing_elems + 1) * sizeof(proto_msg_def_t *));
	msg->entry[existing_elems] = elem;
	msg->entries = existing_elems + 1;
}

void
proto_msg_add_oneof(proto_msg_t *msg, proto_msg_oneof_t *oneof) {
	size_t existing_oneofs = msg->oneofs;
	msg->oneof = realloc(msg->oneof, (existing_oneofs + 1) * sizeof(proto_msg_oneof_t *));
	msg->oneof[existing_oneofs] = oneof;
	msg->oneofs = existing_oneofs + 1;
}

void proto_oneof_add_elem(proto_msg_oneof_t *oneof, proto_msg_def_t *elem) {
	size_t existing_elems = oneof->entries;
	oneof->entry = realloc(oneof->entry, (existing_elems + 1) * sizeof(proto_msg_def_t *));
	oneof->entry[existing_elems] = elem;
	oneof->entries = existing_elems + 1;
}

void
proto_messages_add_msg(proto_module_t *proto_module, proto_msg_t *msg) {
	// ToDo - before adding message to the message stack, we should check if
	//  message with the same name and same signature already exists
	size_t existing_count = proto_module->messages;
	proto_module->message = realloc(proto_module->message, (existing_count + 1) * sizeof(proto_msg_t *));
	proto_module->message[existing_count] = msg;
	proto_module->messages = existing_count + 1;
}

void proto_msg_add_nested(proto_msg_t *msg, proto_msg_t *nested) {
	size_t existing_nesteds = msg->nesteds;
	msg->nested = realloc(msg->nested, (existing_nesteds + 1) * sizeof(proto_msg_t *));
	msg->nested[existing_nesteds] = nested;
	msg->nesteds = existing_nesteds + 1;
}

proto_import_t *
proto_create_import(const char *path, asn1p_oid_t *oid) {
	proto_import_t *protoimport = malloc(sizeof(proto_import_t));
	memset(protoimport, 0, sizeof(proto_import_t));
	strcpy(protoimport->path, path);
	if (oid != NULL)
		protoimport->oid = oid;
	return protoimport;
}

// tags_sum function returns sum of the tags. It is later used in the if condition statement to check, if the tags are
// not empty. If the sum is non-zero, tags are printed. If the sum is zero, tags are not printed.
// Also, assuming that either valueLB and valueUB, or sizeLB and sizeUB are not set (i.e. one pair is [-1, -1]).
// Otherwise there is a possibility that the limits of the long data type would be exceeded.
long
tags_sum(proto_tags_t tags) {

	// avoiding the case when tags for sizeLB, sizeUB, valueLB and valueUB are not set (both are == -1).
	// rest of tags are binary values (either 0, or 1)

	// it doesn't let the case when the actual sizeLB = -1 and sizeUB > sizeLB to go through
	long sizeLB = 0;
	if (tags.sizeLB == -1 && tags.sizeUB == tags.sizeLB) {
		sizeLB = 0;
	} else {
		sizeLB = tags.sizeLB;
	}

	// it doesn't let the case when the actual sizeUB = -1 and sizeUB > sizeLB to go through
	long sizeUB = 0;
	if (tags.sizeUB == -1 && tags.sizeUB == tags.sizeLB) {
		sizeUB = 0;
	} else {
		sizeUB = tags.sizeUB;
	}

	// it doesn't let the case when the actual valueLB = -1 and valueUB > valueLB to go through
	long valueLB = 0;
	if (tags.valueLB == -1 && tags.valueLB == tags.valueUB) {
		valueLB = 0;
	} else {
		valueLB = tags.valueLB;
	}

	// it doesn't let the case when the actual valueLB = -1 and valueUB > valueLB to go through
	long valueUB = 0;
	if (tags.valueUB == -1 && tags.valueLB == tags.valueUB) {
		valueUB = 0;
	} else {
		valueUB = tags.valueUB;
	}

	return tags.optional + tags.sizeExt + sizeLB + sizeUB + tags.valueExt +
		   valueLB + valueUB + tags.repeated + tags.choiceExt + tags.fromChoiceExt +
		   tags.fromValueExt + tags.canonicalOrder + tags.unique;
}
