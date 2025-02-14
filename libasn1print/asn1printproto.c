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
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>

#include <asn1parser.h>
#include <asn1fix_export.h>
#include <asn1p_integer.h>
#include <asn1print.h>

#include "asn1printproto.h"
#include "asn1prototypes.h"

static abuf all_output_;

char usual_class_identifiers[USUAL_CLASS_IDENTIFIERS][USUAL_CLASS_IDENTIFIER_LEN] = {
		{USUAL_CLASS_IDENTIFIER_1},
		{USUAL_CLASS_IDENTIFIER_2}
};

typedef enum {
	PRINT_STDOUT,
	GLOBAL_BUFFER,
} print_method_e;
static print_method_e print_method_;

static char *
proto_constraint_print(const asn1p_constraint_t *ct, enum asn1print_flags2 flags, long *lowerbound, long *upperbound,
					   int *extensibility);

static char *proto_value_print(const asn1p_value_t *val, enum asn1print_flags flags, long *bound);

static int proto_process_enumerated(asn1p_expr_t *expr, proto_enum_t **protoenum);

void parse_constraints_enumerated(asn1p_expr_t *expr, int *elCount, int *extensibility);

static int proto_process_children(asn1p_expr_t *expr, proto_msg_t *msgdef, int repeated, int oneof, int *extensibility,
								  proto_module_t *proto_module, asn1p_t *asn);

static int proto_extract_referenced_message(const char *refName, const char *msgName, proto_module_t *proto_module,
                                            enum asn1print_flags2 flags, asn1p_t *asn);

static int process_referenced_class(const char *className, int *unique, char *choicePart, asn1p_t *asn);
static int get_choice_part(asn1p_expr_t *member, char *choicePart);

static int process_class_referenced_message(asn1p_expr_t *expr, proto_module_t *proto_module, asn1p_t *asn, int isValueSet,
											asn1p_expr_t *constainedSkeleton);
static char *find_referenced_message(char *class_name, asn1p_ioc_row_t *referenced_fields, asn1p_t *asn);

void find_and_process_referenced_type(const char *refType, asn1p_t *asn, proto_msg_def_t *elem,
									  proto_module_t *proto_module, char *constrainedType, int *matched);
static int find_and_get_referenced_message(asn1p_t *asn, asn1p_expr_t *refMsg, char *referencedStructName);

static char *escapeQuotesDup(const char *original);

/* Pedantically check fwrite's return value. */
static size_t safe_fwrite(const void *ptr, size_t size) {
	size_t ret;

	switch (print_method_) {
		case PRINT_STDOUT:
			ret = fwrite(ptr, 1, size, stdout);
			assert(ret == size);
			break;
		case GLOBAL_BUFFER:
			abuf_add_bytes(&all_output_, ptr, size);
			ret = size;
			break;
	}

	return ret;
}

static char
*escapeQuotesDup(const char *original) {
	int origlen = strlen(original);
	char *escaped = strdup(original);
	int added = 0;
	int i = 0;
	while (original[i]) {
		if (original[i] == '\"') {
			escaped = (char *) realloc(escaped, (origlen + added + 1) * sizeof(char));
			escaped[i + added] = '\\';
			escaped[i + added + 1] = original[i];
			added++;
		} else {
			escaped[i + added] = original[i];
		}
		i++;
	}
	escaped[origlen + added] = '\0';
	return escaped;
}

static proto_param_kind_e
proto_param_type(struct asn1p_param_s *param) {
	char *governer = param->governor->components->name;
	char *arg = param->argument;

	//    if (strlen(governer) == 0) {
//        // All caps means class/type
//        // Start with cap means type
//        // Start with cap means type
//    } else if (param->governor->components->lex_type == ){
//        // Start with lowercase means value
//        // Starts with upper case
//    }
	// FIXME: For now just discriminating between Type, Value and Value Set
	return !strlen(governer) ? PROTO_PARAM_TYPE
							 : islower(arg[0]) ? PROTO_PARAM_VALUE
											   : PROTO_PARAM_VALUE_SET;
}

static char *
format_bit_vector_const(asn1p_value_t *v) {
	char *managedptr = NULL;
	uint8_t *bitvector;
	char *ptr;
	size_t len;
	int i = 0;
	/*
	 * Compute number of bytes necessary
	 * to represent the binary value.
	 */
	int bits = v->value.binary_vector.size_in_bits;
	len = ((bits % 8) ? ((bits >> 2) + 1) * 2 : (bits >> 2) * 2);
	managedptr = malloc(len);
	memset(managedptr, 0, len);
	/*
	 * Fill the buffer.
	 */
	ptr = managedptr;
	bitvector = v->value.binary_vector.bits;
	static const char *hextable = "0123456789ABCDEF";
	int extra = bits % 8;
	if (extra) {
		*ptr++ = '\\';
		*ptr++ = 'x';
		*ptr++ = '0';
		*ptr++ = hextable[bitvector[0] >> extra];

		for (i = 1; i < ((bits + 8 - extra) >> 3); i++) {
			*ptr++ = '\\';
			*ptr++ = 'x';
			*ptr++ = hextable[bitvector[i - 1] & 0x0f];
			*ptr++ = hextable[bitvector[i] >> 4];
		}
	} else {
		for (i = 0; i < ((bits) >> 3); i++) {
			*ptr++ = '\\';
			*ptr++ = 'x';
			*ptr++ = hextable[bitvector[i] >> 4];
			*ptr++ = hextable[bitvector[i] & 0x0f];
		}
	}
	if (len != (size_t)(ptr - managedptr)) {
		fprintf(stderr, "unexpected. Bits %d. len %lu != %lu\n", bits, len, (size_t)(ptr - managedptr));
	}
	assert(len == (size_t)(ptr - managedptr));
	return managedptr;
}

static char *
proto_extract_params(proto_msg_t *msg, asn1p_expr_t *expr) {
	char *params_comments = malloc(PROTO_COMMENTS_CHARS);
	memset(params_comments, 0, PROTO_COMMENTS_CHARS);
	char temp[PROTO_COMMENTS_CHARS] = {};
	for (int i = 0; i < expr->lhs_params->params_count; i++) {
		struct asn1p_param_s *param = &expr->lhs_params->params[i];
		proto_param_t *pp = malloc(sizeof(proto_param_t));
		memset(pp, 0, sizeof(proto_param_t));
		pp->kind = proto_param_type(param);
		strcpy(pp->name, param->argument);

		proto_msg_add_param(msg, pp);

		sprintf(temp, "\nParam %s:%s", param->governor->components->name, param->argument);
		strncat(params_comments, temp, PROTO_COMMENTS_CHARS - strlen(params_comments));
	}

	return params_comments;
}

// structure_is_extensible function returns 1 if the referred structure can be extended (contains extension flag)
// or 1, if it doesn't. It also puts 1 in oneofDependent variable, if the structure is of type CHOICE.
// Iteration over the ASN.1 tree is recursive.
static int
structure_is_extensible(asn1p_t *asn, const char *name, int *oneofDependent) {
	int extensibility = 0;

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next)
    {
        asn1p_expr_t *tc;
        TQ_FOR(tc, &(mod->members), next)
        {
            if (strcmp(tc->Identifier, name) == 0) {
                if (tc->expr_type == ASN_CONSTR_CHOICE) {
                    *oneofDependent = 1;
                }
                asn1p_expr_t *se;
                if (TQ_FIRST(&tc->members)) {
                    TQ_FOR(se, &(tc->members), next)
                    {
                        if (se->expr_type == A1TC_EXTENSIBLE) {
                            extensibility = 1;
                            break;
                        }
                    }
                }
            }
        }
    }

	return extensibility;
}

static int
get_extensibility(const asn1p_constraint_t *ct) {
	int i = 0;
	int result = 0;

	if (ct != NULL) {
		switch (ct->type) {
			case ACT_EL_EXT:
				// this is to parse extension flag for basic types (e.g., INTEGER, BIT STRING, etc.)
				result = 1;
				break;
			default:
				result = 0;
				break;
		}


		for (i = 0; i < ct->el_count; i++) {
			result = get_extensibility(ct->elements[i]);
			if (result != 0) {
				// extensibility flag was found
				break;
			}
		}
	}

	return result;
}

static long
get_lowerbound(const asn1p_constraint_t *ct) {

	int i = 0;
	long result = -1;

	if (ct->el_count == 0) {
		// we are at the bottom, extract a lowerbound
		if (ct->range_start != NULL) {
			switch (ct->range_start->type) {
				case ATV_INTEGER:
					result = (long) ct->range_start->value.v_integer;
					return result;
					/*
							case ATV_NULL:
								strcat(result, "NULL");
								return result;
					*/
				case ATV_MIN:
					result = -2147483648;
					return result;
				case ATV_MAX:
					result = 2147483648;
					return result;
				default:
					return -1;
			}
		} else {
			switch (ct->value->type) {
				case ATV_INTEGER:
					result = (long) ct->value->value.v_integer;
					return result;
					/*
							case ATV_NULL:
								strcat(result, "NULL");
								return result;
					*/
				case ATV_MIN:
					result = -2147483648;
					return result;
				case ATV_MAX:
					result = 2147483648;
					return result;
				default:
					return -1;
			}
		}
	}

	for (i = 0; i < ct->el_count; i++) {
		result = get_lowerbound(ct->elements[i]);
		if (result != -1) {
			// found the constraint
			break;
		}
	}

	return result;
}

static long
get_upperbound(const asn1p_constraint_t *ct) {

	int i = 0;
	long result = -1;

	if (ct->el_count == 0) {
		// we are at the bottom, extract a lowerbound
		if (ct->range_stop != NULL) {
			switch (ct->range_stop->type) {
				case ATV_INTEGER:
					result = (long) ct->range_stop->value.v_integer;
					return result;
					/*
							case ATV_NULL:
								strcat(result, "NULL");
								return result;
					*/
				case ATV_MIN:
					result = -2147483648;
					return result;
				case ATV_MAX:
					result = 2147483648;
					return result;
				default:
					return -1;
			}
		} else {
			switch (ct->value->type) {
				case ATV_INTEGER:
					result = (long) ct->value->value.v_integer;
					return result;
					/*
							case ATV_NULL:
								strcat(result, "NULL");
								return result;
					*/
				case ATV_MIN:
					result = -2147483648;
					return result;
				case ATV_MAX:
					result = 2147483648;
					return result;
				default:
					return -1;
			}
		}
	}

	for (i = 0; i < ct->el_count; i++) {
		result = get_upperbound(ct->elements[i]);
		if (result != -1) {
			// found the constraint
			break;
		}
	}

	return result;
}

static int
add_message_from_expression(const char *refName, const char *msgName, asn1p_expr_t *expr, asn1p_module_t *mod,
							proto_module_t *proto_module, enum asn1print_flags2 flags, asn1p_t *asn) {
	if (!expr->Identifier) return 1;

	if (expr->expr_type == ASN_BASIC_ENUMERATED) {
		proto_enum_t *newenum = proto_create_enum(msgName,
												  "enumerated from %s:%d", mod->source_file_name, expr->_lineno);
		proto_process_enumerated(expr, &newenum);
		proto_enums_add_enum(proto_module, newenum);

	} else if (expr->meta_type == AMT_VALUE) {
		proto_msg_t *msg;
		proto_msg_def_t *msgelem;
		switch (expr->expr_type) {
			case ASN_BASIC_INTEGER:
				msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
										   "constant Integer from %s:%d", mod->source_file_name, expr->_lineno, 1);
				msgelem = proto_create_msg_elem("value", "int32", NULL);
				if ((long) expr->value->value.v_integer > 2147483647 ||
					(long) expr->value->value.v_integer < -2147483647) {
					sprintf(msgelem->rules, "int64.const = %ld", (long) expr->value->value.v_integer);
					strcpy(msgelem->type, "int64");
					msgelem->tags.valueLB = (long) expr->value->value.v_integer;
					msgelem->tags.valueUB = (long) expr->value->value.v_integer;
				} else {
					sprintf(msgelem->rules, "int32.const = %d", (int) expr->value->value.v_integer);
					msgelem->tags.valueLB = (int) expr->value->value.v_integer;
					msgelem->tags.valueUB = (int) expr->value->value.v_integer;
				}
				// ToDo - this should add a non-zero value to the unique tag (used in E2AP), but it doesn't. Figure out why.
				msgelem->tags.unique = (int) expr->unique;
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);

				return 0;
			case ASN_BASIC_RELATIVE_OID:
				msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
										   "constant Basic OID from %s:%d", mod->source_file_name, expr->_lineno, 1);
				msgelem = proto_create_msg_elem("value", "string", NULL);
				sprintf(msgelem->rules, "string.const = '%s'", asn1f_printable_value(expr->value));
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);

				break;
			case ASN_BASIC_OCTET_STRING:
				msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
										   "constant Basic OCTET STRING from %s:%d", mod->source_file_name,
										   expr->_lineno, 1);
				msgelem = proto_create_msg_elem("value", "bytes", NULL);
				char *byte_string = NULL;
				switch (expr->value->type) {
					case ATV_BITVECTOR:
						byte_string = format_bit_vector_const(expr->value);
						break;
					default:
						fprintf(stderr, "Unhandled conversion of OCTET_STRING const from type %d", expr->value->type);
				}
				sprintf(msgelem->rules, "bytes.const = '%s'", byte_string);
				free((void *) byte_string);
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);

				break;
			case A1TC_REFERENCE:
				msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
										   "reference from %s:%d", mod->source_file_name, expr->_lineno, 0);
				msgelem = proto_create_msg_elem("value", "int32", NULL);

				for (size_t cc = 0; cc < expr->reference->comp_count; cc++) {
					if (cc) strcat(msgelem->comments, ".");
					strcat(msgelem->comments, expr->reference->components[cc].name);
				}

				switch (expr->value->type) {
					case ATV_INTEGER: // INTEGER
						if ((long) expr->value->value.v_integer > 2147483647 ||
							(long) expr->value->value.v_integer < -2147483647) {
							sprintf(msgelem->rules, "int64.const = %ld", (long) expr->value->value.v_integer);
							strcpy(msgelem->type, "int64");
							msgelem->tags.valueLB = (long) expr->value->value.v_integer;
							msgelem->tags.valueUB = (long) expr->value->value.v_integer;

						} else {
							sprintf(msgelem->rules, "int32.const = %d", (int) expr->value->value.v_integer);
							msgelem->tags.valueLB = (int) expr->value->value.v_integer;
							msgelem->tags.valueUB = (int) expr->value->value.v_integer;
						}
						proto_msg_add_elem(msg, msgelem);
						proto_messages_add_msg(proto_module, msg);
						return 0;
					case ATV_STRING:
						strcpy(msgelem->type, "string");
						char *escaped = escapeQuotesDup((char *) expr->value->value.string.buf);
						snprintf(msgelem->rules, 100, "string.const = \"%s\"", escaped);
						free(escaped);
						proto_msg_add_elem(msg, msgelem);
						proto_messages_add_msg(proto_module, msg);
						return 0;
					case ATV_UNPARSED:
						if (expr->ioc_table != NULL) {
                            process_class_referenced_message(expr, proto_module, asn, 1, NULL);
						}
						break;
					default:
						fprintf(stderr, "// Error. AMT_VALUE with ExprType: %d\n", expr->value->type);
				}

				return 0;
			default:
				fprintf(stderr, "ERROR: unhandled expr->expr_type %d\n", expr->expr_type);
				return -1;
		}
	} else if (expr->expr_type == ASN_BASIC_INTEGER && expr->meta_type == AMT_VALUESET) {
		proto_msg_t *msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
												"range of Integer from %s:%d", mod->source_file_name, expr->_lineno, 0);
		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);
		long lowerbound = -1;
		long upperbound = -1;
		int extensibility = 0;
		char *constraints = proto_constraint_print(expr->constraints, flags, &lowerbound, &upperbound, &extensibility);
		if (lowerbound != -1) {
			msgelem->tags.valueLB = lowerbound;
		}
		if (upperbound != -1) {
			msgelem->tags.valueUB = upperbound;
		}
		if (extensibility) {
			msgelem->tags.valueExt = 1;
		}
		sprintf(msgelem->rules, "int32 = {in: [%s]}", constraints);
		free(constraints);
		proto_msg_add_elem(msg, msgelem);
		proto_messages_add_msg(proto_module, msg);

		return 0;
	} else if (expr->meta_type == AMT_TYPE &&
			   expr->expr_type != ASN_CONSTR_SEQUENCE &&
			   expr->expr_type != ASN_CONSTR_SEQUENCE_OF &&
			   expr->expr_type != ASN_CONSTR_CHOICE) {
		proto_msg_t *msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
												"range of Integer from %s:%d", mod->source_file_name, expr->_lineno, 0);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);

		switch (expr->expr_type) {
			case ASN_BASIC_INTEGER:
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraints = proto_constraint_print(expr->constraints, flags | APF_INT32_VALUE, &lowerbound,
															   &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.valueExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.valueLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.valueUB = upperbound;
					}
					if (lowerbound < -2147483647 || upperbound > 2147483647) {
						sprintf(msgelem->rules, "int64 = {%s}", constraints);
						strcpy(msgelem->type, "int64");
					} else {
						sprintf(msgelem->rules, "int32 = {%s}", constraints);
					}
					free(constraints);
					// TODO: Find why 07 test does not show Reason values
				}
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_STRING_IA5String:
			case ASN_STRING_BMPString:
				strcpy(msgelem->type, "string");
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraints = proto_constraint_print(expr->constraints, flags | APF_STRING_VALUE, &lowerbound,
															   &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					sprintf(msgelem->rules, "string = {%s}", constraints);
					free(constraints);
				}
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_BASIC_BOOLEAN:
				strcpy(msgelem->type, "bool");
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_BASIC_BIT_STRING:
				strcpy(msgelem->type, "asn1.v1.BitString");
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound;
					lowerbound = get_lowerbound(expr->constraints);
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					// obtaining upperbound
					long upperbound;
					upperbound = get_upperbound(expr->constraints);
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					int extensibility;
					extensibility = get_extensibility(expr->constraints);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
				}
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_BASIC_OCTET_STRING:
				strcpy(msgelem->type, "bytes");
				// adding constraints
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(expr->constraints, APF_BYTES_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					sprintf(msgelem->rules, "bytes = {%s}", constraint);
					free(constraint);
				}

				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_STRING_PrintableString:
				strcpy(msgelem->type, "string");
				// adding constraints
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(expr->constraints, APF_STRING_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					sprintf(msgelem->rules, "string = {%s}", constraint);
					free(constraint);
				}

				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			default:
				// by default storing tags for sizeLB and sizeUB
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound;
					lowerbound = get_lowerbound(expr->constraints);
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					// obtaining upperbound
					long upperbound;
					upperbound = get_upperbound(expr->constraints);
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					int extensibility;
					extensibility = get_extensibility(expr->constraints);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
				}
				// adding message elements to the message itself
				proto_msg_add_elem(msg, msgelem);
				// adding message to the Protobuf tree
				proto_messages_add_msg(proto_module, msg);

				// to indicate that we've hit something unexpected
				fprintf(stderr, "unhandled expr_type: %d and meta_type: %d\n", expr->expr_type, expr->meta_type);
				return 0;
		}
		return 0;
	} else if (expr->meta_type == AMT_TYPE &&
			   (expr->expr_type == ASN_CONSTR_SEQUENCE ||
				expr->expr_type == ASN_CONSTR_SEQUENCE_OF)) {
		proto_msg_t *msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
												"sequence from %s:%d", mod->source_file_name, expr->_lineno, 0);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		int extensibility = 0;
		proto_process_children(expr, msg, expr->expr_type == ASN_CONSTR_SEQUENCE_OF, 0, &extensibility, proto_module, asn);
		if (extensibility) {
			strcat(msg->comments, "\n@inject_tag: aper:\"valueExt\"");
		}

		proto_messages_add_msg(proto_module, msg);

	} else if (expr->meta_type == AMT_TYPE && expr->expr_type == ASN_CONSTR_CHOICE) {
		proto_msg_t *msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
												"sequence from %s:%d", mod->source_file_name, expr->_lineno, 0);

		// TODO: Determine if comments should belong to the oneof or to the parent message.
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_oneof_t *oneof = proto_create_msg_oneof(msgName,
														  "choice from %s:%d", mod->source_file_name, expr->_lineno);
		proto_msg_add_oneof(msg, oneof);

		int extensibility = 0;
		proto_process_children(expr, (proto_msg_t *) oneof, 0, 1, &extensibility, proto_module, asn);
		if (extensibility) {
			strcat(msg->comments, "\n@inject_tag: aper:\"choiceExt\"");
		}

		proto_messages_add_msg(proto_module, msg);

	} else if (expr->meta_type == AMT_TYPEREF) {
		proto_msg_t *msg = proto_create_message(msgName, expr->spec_index, expr->_type_unique_index,
												"reference from %s:%d", mod->source_file_name, expr->_lineno, 0);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);

		if (expr->reference->comp_count >= 1) {
			asn1p_expr_t *refElem;
			refElem = WITH_MODULE_NAMESPACE(expr->module, expr_ns, asn1f_find_terminal_type_ex(asn, expr_ns, expr));
			sprintf(msgelem->type, "%s%03d", refElem->Identifier, refElem->_type_unique_index);
            int res = 0;
            res = proto_extract_referenced_message(refElem->Identifier, msgelem->type, proto_module, flags, asn);
            // now add this message to the message tree
            if (res) {
                fprintf(stderr, "\n\n//////// ERROR Couldn't create message. Unhandled expr %s. Meta type: %d. Expr type: %d /////\n\n",
                        refElem->Identifier, refElem->meta_type, refElem->expr_type);
            }
		}

		// checking if the structure is extensible
		int isExtensible = 0;
		int oneofDependent = 0;
		isExtensible = structure_is_extensible(asn, expr->reference->components->name, &oneofDependent);
		if (isExtensible == 1 && oneofDependent == 0) {
			msgelem->tags.valueExt = 1;
		} else if (isExtensible == 1 && oneofDependent == 1) {
			msgelem->tags.choiceExt = 1;
		}

		proto_msg_add_elem(msg, msgelem);

		proto_messages_add_msg(proto_module, msg);
		return 0;

    } else if (expr->meta_type == AMT_VALUESET && expr->expr_type == A1TC_REFERENCE) {
        char refname[PROTO_NAME_CHARS] = {};
        if (expr->reference && expr->reference->comp_count > 0) {
            strcpy(refname, expr->reference->components[0].name);
        }
        process_class_referenced_message(expr, proto_module, asn, 1, NULL);
        return 0;
    } else {
        fprintf(stderr, "\n\n//////// ERROR Unhandled expr %s. Meta type: %d. Expr type: %d /////\n\n",
                expr->Identifier, expr->meta_type, expr->expr_type);
    }
	return 0;
}

static int
proto_extract_referenced_message(const char *refName, const char *msgName, proto_module_t *proto_module,
                                 enum asn1print_flags2 flags, asn1p_t *asn) {
	int res = 0;

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next)
    {
        asn1p_expr_t *tc;
        TQ_FOR(tc, &(mod->members), next)
        {
            if (strcmp(tc->Identifier, refName) == 0) {
                // Creating and adding a message
                res = add_message_from_expression(refName, msgName, tc, mod, proto_module, flags, asn);
                return res;
            }
        }
    }

	return res;
}

// find_and_process_referenced_type() function processes field of the message as a referred type and parses constraints.
// So far only lists (SEQUENCE OF) can be parsed. This is because they are mainly defined in E2AP.
void
find_and_process_referenced_type(const char *refType, asn1p_t *asn, proto_msg_def_t *elem,
								 proto_module_t *proto_module, char *constrainedType, int *matched) {

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next)
    {
        asn1p_expr_t *tc;
        TQ_FOR(tc, &(mod->members), next)
        {
            if (strcmp(tc->Identifier, refType) == 0) {
                *matched = 1;
                // found the referenced message, cloning it to the element
                if (tc->expr_type == ASN_CONSTR_SEQUENCE_OF) {
                    elem->tags.repeated = 1;
                    int lb = get_lowerbound(tc->constraints);
                    if (lb != -1) {
                        elem->tags.sizeLB = lb;
                    }
                    int ub = get_upperbound(tc->constraints);
                    if (ub != -1) {
                        elem->tags.sizeUB = ub;
                    }
                    int extensibility;
                    extensibility = get_extensibility(tc->constraints);
                    if (extensibility) {
                        elem->tags.sizeExt = 1;
                    }
                }
                // ToDo - add handling of other types..
                // composing a referenced message
                if (tc->lhs_params != NULL) {
                    // if it is not nil, then it can be referenced

                    // understanding, if a field of this message requires specific type
                    asn1p_expr_t *innerSe;
                    if (TQ_FIRST(&tc->members)) {
                        TQ_FOR(innerSe, &(tc->members), next)
                        {
                            // handling the case when item of the type is referenced with another type
                            if (innerSe->meta_type == AMT_TYPEREF && innerSe->expr_type == A1TC_REFERENCE) {
                                strcpy(constrainedType, innerSe->reference->components->name);
                                fprintf(stderr, "Hooray! Constrained type was found, it is %s!\n", innerSe->reference->components->name);
                            }
                        }
                    }

                }
                return;
            }
        }
    }

	return;
}

static int
find_and_get_referenced_message(asn1p_t *asn, asn1p_expr_t *refMsg, char *referencedStructName) {

	int res = 0;

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next)
    {
        asn1p_expr_t *tc;
        TQ_FOR(tc, &(mod->members), next)
        {
            if (strcmp(tc->Identifier, referencedStructName) == 0) {
                // then copy it over to the target one
                memcpy(refMsg, tc, sizeof(*tc));
                fprintf(stderr, "find_and_get_referenced_message(): Hooray! Constrained skeleton was found! It is %s\n",
                        refMsg->Identifier);
                res = 1;
                return res;
            }
        }
    }

	return res;
}

static int
process_referenced_class(const char *className, int *unique, char *choicePart, asn1p_t *asn) {
	int res = 0;

	asn1p_module_t *mod;
	TQ_FOR(mod, &(asn->modules), mod_next)
	{
		asn1p_expr_t *tc;
		TQ_FOR(tc, &(mod->members), next)
		{
			if (strcmp(tc->Identifier, className) == 0) {
				fprintf(stderr, "process_referenced_class(): CLASS %s was found!\n", tc->Identifier);
				// searching for unique and choice part
				if (tc->ioc_table != NULL) {
					int rowIdx = 0;
					for (rowIdx = 0; rowIdx < (int) tc->ioc_table->rows; rowIdx++) {
						asn1p_ioc_row_t *table_row = tc->ioc_table->row[rowIdx];

						// making sure that the unique tag is present
						int colIdx = 0;
						for (colIdx = 0; colIdx < (int) table_row->columns; colIdx++) {
							struct asn1p_ioc_cell_s colij = table_row->column[colIdx];
							if (colij.field->unique) {
								*unique = 1;
								break;
							}
						}
					}
					if (tc->members.tq_head != NULL) {
						get_choice_part(tc->members.tq_head, choicePart);
					}
					res = 1;
					return res;
				}
			}
		}
	}

	return res;
}

// this function extract the choice part name for the value set
static int
get_choice_part(asn1p_expr_t *member, char *choicePart) {
	int res = 0;

	// iterate over tree members and get the structure name, which has tree->members.tq_head == NULL
	 if (member->members.tq_head != NULL) {
		if (member->members.tq_head->expr_type == ASN_TYPE_ANY) {
			// this is the choice part
			strcat(choicePart, member->Identifier);
			return 1;
		} else {
			if (member->next.tq_next != NULL) {
				res = get_choice_part(member->next.tq_next, choicePart);
				return res;
			}
		}
	} else if (member->members.tq_head == NULL) {
		 // this is the choice part
		 strcat(choicePart, member->Identifier);
		 return 1;
	 } else {
		if (member->next.tq_next != NULL) {
			res = get_choice_part(member->next.tq_next, choicePart);
			return res;
		}
	}

	return res;
}

int
asn1print_expr_proto(asn1p_t *asn, asn1p_module_t *mod, asn1p_expr_t *expr,
					 proto_module_t *proto_module,
					 enum asn1print_flags2 flags) {
	if (mod != NULL) {
		// A dummy placeholder to avoid coverage errors
	}

	fprintf(stderr, "-------------------> asn1print_expr_proto(): Processing structure %s\n", expr->Identifier);
	// If there are specializations (driven by parameters, define these as proto messages)
	if (expr->specializations.pspecs_count > 0) {
		int i;
		int ret;
		for (i = 0; i < expr->specializations.pspecs_count; i++) {
			asn1p_expr_t *spec_clone = expr->specializations.pspec[i].my_clone;
			ret = asn1print_expr_proto(asn, mod, spec_clone, proto_module, flags);
			if (ret != 0) {
				return ret;
			}
		}
		return 0;
	};

	if (!expr->Identifier) return 0;

	if (expr->expr_type == ASN_BASIC_ENUMERATED) {
		proto_enum_t *newenum = proto_create_enum(expr->Identifier,
												  "enumerated from %s:%d", mod->source_file_name, expr->_lineno);
		proto_process_enumerated(expr, &newenum);
		proto_enums_add_enum(proto_module, newenum);

	} else if (expr->meta_type == AMT_VALUE) {
		proto_msg_t *msg;
		proto_msg_def_t *msgelem;
		switch (expr->expr_type) {
			case ASN_BASIC_INTEGER:
				msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
										   "constant Integer from %s:%d", mod->source_file_name, expr->_lineno, 1);
				msgelem = proto_create_msg_elem("value", "int32", NULL);
				if ((long) expr->value->value.v_integer > 2147483647 ||
					(long) expr->value->value.v_integer < -2147483647) {
					sprintf(msgelem->rules, "int64.const = %ld", (long) expr->value->value.v_integer);
					strcpy(msgelem->type, "int64");
					msgelem->tags.valueLB = (long) expr->value->value.v_integer;
					msgelem->tags.valueUB = (long) expr->value->value.v_integer;
				} else {
					sprintf(msgelem->rules, "int32.const = %d", (int) expr->value->value.v_integer);
					msgelem->tags.valueLB = (int) expr->value->value.v_integer;
					msgelem->tags.valueUB = (int) expr->value->value.v_integer;
				}
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);

				return 0;
			case ASN_BASIC_RELATIVE_OID:
				msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
										   "constant Basic OID from %s:%d", mod->source_file_name, expr->_lineno, 1);
				msgelem = proto_create_msg_elem("value", "string", NULL);
				sprintf(msgelem->rules, "string.const = '%s'", asn1f_printable_value(expr->value));
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);

				break;
			case ASN_BASIC_OCTET_STRING:
				msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
										   "constant Basic OCTET STRING from %s:%d", mod->source_file_name,
										   expr->_lineno, 1);
				msgelem = proto_create_msg_elem("value", "bytes", NULL);
				char *byte_string = NULL;
				switch (expr->value->type) {
					case ATV_BITVECTOR:
						byte_string = format_bit_vector_const(expr->value);
						break;
					default:
						fprintf(stderr, "Unhandled conversion of OCTET_STRING const from type %d", expr->value->type);
				}
				sprintf(msgelem->rules, "bytes.const = '%s'", byte_string);
				free((void *) byte_string);
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);

				break;
			case A1TC_REFERENCE:
				// ToDo - CLASS inheritance may require some rework here..
				msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
										   "reference from %s:%d", mod->source_file_name, expr->_lineno, 0);
				msgelem = proto_create_msg_elem("value", "int32", NULL);

				for (size_t cc = 0; cc < expr->reference->comp_count; cc++) {
					if (cc) strcat(msgelem->comments, ".");
					strcat(msgelem->comments, expr->reference->components[cc].name);
				}

				switch (expr->value->type) {
					case ATV_INTEGER: // INTEGER
						if ((long) expr->value->value.v_integer > 2147483647 ||
							(long) expr->value->value.v_integer < -2147483647) {
							sprintf(msgelem->rules, "int64.const = %ld", (long) expr->value->value.v_integer);
							strcpy(msgelem->type, "int64");
							msgelem->tags.valueLB = (long) expr->value->value.v_integer;
							msgelem->tags.valueUB = (long) expr->value->value.v_integer;

						} else {
							sprintf(msgelem->rules, "int32.const = %d", (int) expr->value->value.v_integer);
							msgelem->tags.valueLB = (int) expr->value->value.v_integer;
							msgelem->tags.valueUB = (int) expr->value->value.v_integer;
						}
						proto_msg_add_elem(msg, msgelem);
						proto_messages_add_msg(proto_module, msg);
						return 0;
					case ATV_STRING:
						strcpy(msgelem->type, "string");
						char *escaped = escapeQuotesDup((char *) expr->value->value.string.buf);
						snprintf(msgelem->rules, 100, "string.const = \"%s\"", escaped);
						free(escaped);
						proto_msg_add_elem(msg, msgelem);
						proto_messages_add_msg(proto_module, msg);
						return 0;
					case ATV_UNPARSED:
						// ToDo: Regular messages, which are defined through CLASS are processed here..
						if (expr->ioc_table != NULL) {
							process_class_referenced_message(expr, proto_module, asn, 0, NULL);
						}
						break;
					default:
						fprintf(stderr, "// Error. AMT_VALUE with ExprType: %d\n", expr->value->type);
				}

				return 0;
			default:
				fprintf(stderr, "ERROR: unhandled expr->expr_type %d\n", expr->expr_type);
				return -1;
		}
	} else if (expr->expr_type == ASN_BASIC_INTEGER && expr->meta_type == AMT_VALUESET) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
												"range of Integer from %s:%d", mod->source_file_name, expr->_lineno, 0);
		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);
		long lowerbound = -1;
		long upperbound = -1;
		int extensibility = 0;
		char *constraints = proto_constraint_print(expr->constraints, flags, &lowerbound, &upperbound, &extensibility);
		if (lowerbound != -1) {
			msgelem->tags.valueLB = lowerbound;
		}
		if (upperbound != -1) {
			msgelem->tags.valueUB = upperbound;
		}
		if (extensibility) {
			msgelem->tags.valueExt = 1;
		}
		sprintf(msgelem->rules, "int32 = {in: [%s]}", constraints);
		free(constraints);
		proto_msg_add_elem(msg, msgelem);
		proto_messages_add_msg(proto_module, msg);

		return 0;
	} else if (expr->meta_type == AMT_TYPE &&
			   expr->expr_type != ASN_CONSTR_SEQUENCE &&
			   expr->expr_type != ASN_CONSTR_SEQUENCE_OF &&
			   expr->expr_type != ASN_CONSTR_CHOICE) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
												"range of Integer from %s:%d", mod->source_file_name, expr->_lineno, 0);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);

		switch (expr->expr_type) {
			case ASN_BASIC_INTEGER:
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraints = proto_constraint_print(expr->constraints, flags | APF_INT32_VALUE, &lowerbound,
															   &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.valueExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.valueLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.valueUB = upperbound;
					}
					if (lowerbound < -2147483647 || upperbound > 2147483647) {
						sprintf(msgelem->rules, "int64 = {%s}", constraints);
						strcpy(msgelem->type, "int64");
					} else {
						sprintf(msgelem->rules, "int32 = {%s}", constraints);
					}
					free(constraints);
					// TODO: Find why 07 test does not show Reason values
				}
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_STRING_IA5String:
			case ASN_STRING_BMPString:
				strcpy(msgelem->type, "string");
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraints = proto_constraint_print(expr->constraints, flags | APF_STRING_VALUE, &lowerbound,
															   &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					sprintf(msgelem->rules, "string = {%s}", constraints);
					free(constraints);
				}
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_BASIC_BOOLEAN:
				strcpy(msgelem->type, "bool");
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_BASIC_BIT_STRING:
				strcpy(msgelem->type, "asn1.v1.BitString");
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound;
					lowerbound = get_lowerbound(expr->constraints);
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					// obtaining upperbound
					long upperbound;
					upperbound = get_upperbound(expr->constraints);
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					int extensibility;
					extensibility = get_extensibility(expr->constraints);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
				}
				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_BASIC_OCTET_STRING:
				strcpy(msgelem->type, "bytes");
				// adding constraints
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(expr->constraints, APF_BYTES_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					sprintf(msgelem->rules, "bytes = {%s}", constraint);
					free(constraint);
				}

				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			case ASN_STRING_PrintableString:
				strcpy(msgelem->type, "string");
				// adding constraints
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(expr->constraints, APF_STRING_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					sprintf(msgelem->rules, "string = {%s}", constraint);
					free(constraint);
				}

				proto_msg_add_elem(msg, msgelem);
				proto_messages_add_msg(proto_module, msg);
				return 0;
			default:
				// by default storing tags for sizeLB and sizeUB
				if (expr->constraints != NULL) {
					// adding APER tags
					long lowerbound;
					lowerbound = get_lowerbound(expr->constraints);
					if (lowerbound != -1) {
						msgelem->tags.sizeLB = lowerbound;
					}
					// obtaining upperbound
					long upperbound;
					upperbound = get_upperbound(expr->constraints);
					if (upperbound != -1) {
						msgelem->tags.sizeUB = upperbound;
					}
					int extensibility;
					extensibility = get_extensibility(expr->constraints);
					if (extensibility) {
						msgelem->tags.sizeExt = 1;
					}
				}
				// adding message elements to the message itself
				proto_msg_add_elem(msg, msgelem);
				// adding message to the Protobuf tree
				proto_messages_add_msg(proto_module, msg);

				// to indicate that we've hit something unexpected
				fprintf(stderr, "unhandled expr_type: %d and meta_type: %d\n", expr->expr_type, expr->meta_type);
				return 0;
		}
		return 0;
	} else if (expr->meta_type == AMT_TYPE &&
			   (expr->expr_type == ASN_CONSTR_SEQUENCE ||
				expr->expr_type == ASN_CONSTR_SEQUENCE_OF)) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
												"sequence from %s:%d", mod->source_file_name, expr->_lineno, 0);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		// verifying that it is extra call to add referenced type
		if (flags & APF_REFERENCED_TYPE) {
			sprintf(msg->name, "%s%03d", expr->Identifier, expr->_type_unique_index);
		}

		int extensibility = 0;
		proto_process_children(expr, msg, expr->expr_type == ASN_CONSTR_SEQUENCE_OF, 0, &extensibility, proto_module, asn);
		if (extensibility) {
			strcat(msg->comments, "\n@inject_tag: aper:\"valueExt\"");
		}

		proto_messages_add_msg(proto_module, msg);

	} else if (expr->meta_type == AMT_TYPE && expr->expr_type == ASN_CONSTR_CHOICE) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
												"sequence from %s:%d", mod->source_file_name, expr->_lineno, 0);

		// TODO: Determine if comments should belong to the oneof or to the parent message.
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_oneof_t *oneof = proto_create_msg_oneof(expr->Identifier,
														  "choice from %s:%d", mod->source_file_name, expr->_lineno);
		proto_msg_add_oneof(msg, oneof);

		int extensibility = 0;
		proto_process_children(expr, (proto_msg_t *) oneof, 0, 1, &extensibility, proto_module, asn);

		if (extensibility) {
			strcat(msg->comments, "\n@inject_tag: aper:\"choiceExt\"");
		}

		proto_messages_add_msg(proto_module, msg);

	} else if (expr->expr_type == A1TC_CLASSDEF) {
		// No equivalent of class in Protobuf - ignore
		return 0;

	} else if (expr->meta_type == AMT_TYPEREF) {
		proto_msg_t *msg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
												"reference from %s:%d", mod->source_file_name, expr->_lineno, 0);
		if (expr->lhs_params != NULL) {
			char *param_comments = proto_extract_params(msg, expr);
			strcat(msg->comments, param_comments);
			free(param_comments);
		}

		proto_msg_def_t *msgelem = proto_create_msg_elem("value", "int32", NULL);

		if (expr->reference->comp_count >= 1) {
			asn1p_expr_t *refElem;
			refElem = WITH_MODULE_NAMESPACE(expr->module, expr_ns, asn1f_find_terminal_type_ex(asn, expr_ns, expr));
			sprintf(msgelem->type, "%s%03d", refElem->Identifier, refElem->_type_unique_index);

            int res = 0;
            res = proto_extract_referenced_message(refElem->Identifier, msgelem->type, proto_module, flags, asn);
            // now add this message to the message tree
            if (res) {
                fprintf(stderr, "\n\n//////// ERROR Couldn't create message. Unhandled expr %s -> %s. Meta type: %d. Expr type: %d /////\n\n",
                        refElem->Identifier, msgelem->type, refElem->meta_type, refElem->expr_type);
            }
		}

		// checking if the structure is extensible
		int isExtensible = 0;
		int oneofDependent = 0;
        isExtensible = structure_is_extensible(asn, expr->reference->components->name, &oneofDependent);
		if (isExtensible == 1 && oneofDependent == 0) {
			msgelem->tags.valueExt = 1;
		} else if (isExtensible == 1 && oneofDependent == 1) {
			msgelem->tags.choiceExt = 1;
		}

		proto_msg_add_elem(msg, msgelem);

		proto_messages_add_msg(proto_module, msg);
		return 0;

	} else if (expr->meta_type == AMT_VALUESET && expr->expr_type == A1TC_REFERENCE) {
		char refname[PROTO_NAME_CHARS] = {};
		if (expr->reference && expr->reference->comp_count > 0) {
			strcpy(refname, expr->reference->components[0].name);
		}
		process_class_referenced_message(expr, proto_module, asn, 1, NULL);
		return 0;
	} else {
		fprintf(stderr, "\n\n//////// ERROR Unhandled expr %s. Meta type: %d. Expr type: %d /////\n\n",
				expr->Identifier, expr->meta_type, expr->expr_type);
	}
	return 0;
}

void
parse_constraints_enumerated(asn1p_expr_t *expr, int *elCount, int *extensibility) {
	asn1p_expr_t *se;
	int count = -1;
	TQ_FOR(se, &(expr->members), next)
	{
		if (se->expr_type == A1TC_UNIVERVAL) { // for enum values
			count++;
		} else if (se->expr_type == A1TC_EXTENSIBLE) {
			*extensibility = 1;
			break;
		}
	}
	*elCount = count;
}

static int
proto_process_enumerated(asn1p_expr_t *expr, proto_enum_t **protoenum) {
	asn1p_expr_t *se;
	TQ_FOR(se, &(expr->members), next)
	{
		if (se->expr_type == A1TC_UNIVERVAL) { // for enum values
			proto_enum_def_t *def = proto_create_enum_def(se->Identifier, -1, NULL);
			if (se->value->type == ATV_INTEGER && se->value->value.v_integer >= 0) {
				def->index = se->value->value.v_integer;
			}
			proto_enum_add_def(*protoenum, def);
		}
	}
	return 0;
}

// is_enum function verifies if the parsed structure is enumerator or not.
static int
is_enum(asn1p_t *asn, const char *name, int *elCount) {
	asn1p_expr_t *se;
	int enm = 0;
	int elements = -1;

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next)
    {
        asn1p_expr_t *tc;
        TQ_FOR(tc, &(mod->members), next)
        {
            if (strcmp(tc->Identifier, name) == 0) {
                if (tc->expr_type == ASN_BASIC_ENUMERATED) {
                    enm = 1;
                    if (TQ_FIRST(&tc->members)) {
                        TQ_FOR(se, &(tc->members), next)
                        {
                            if (se->expr_type == A1TC_EXTENSIBLE) {
                                break;
                            }
                            elements++;
                        }
                    }
                }
            }
        }
    }

	*elCount = elements;
	return enm;
}

static int
proto_process_children(asn1p_expr_t *expr, proto_msg_t *msgdef, int repeated, int oneof, int *extensibility,
					   proto_module_t *proto_module, asn1p_t *asn) {
	asn1p_expr_t *se;
	// se2 carries information about the type of the item (could be useful to parse constraints, such as valueExt for SEQUENCEs)
	asn1p_expr_t *se2;
	int children = 0;

	if (TQ_FIRST(&expr->members)) {
		int extensible = 0;
//		if(expr->expr_type == ASN_BASIC_BIT_STRING)
//			dont_involve_children = 1;
		TQ_FOR(se, &(expr->members), next)
		{
			children++;
			proto_msg_def_t *elem = proto_create_msg_elem(se->Identifier, "int32", NULL);
			elem->tags.repeated = repeated;

			// parsing constraints for SEQUENCE OF...
			if (repeated) {
				if (expr->constraints != NULL) {
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(expr->constraints, APF_REPEATED_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						elem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						elem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						elem->tags.sizeUB = upperbound;
					}
					sprintf(elem->rules, "repeated = {%s}", constraint);
					free(constraint);
				}
			}

			elem->marker = se->marker.flags;
			// checking if the structure is optional and adding a tag if it is
			if (elem->marker == EM_OPTIONAL) {
				elem->tags.optional = 1;
			}

			// if extension flag is set, we are iterating over items in extension
			if (extensible && oneof) {
				elem->tags.fromChoiceExt = 1;
			} else if (extensible && oneof == 0) {
				elem->tags.fromValueExt = 1;
			}

			// checking if constraints are not NULL and parsing them (this is for all types except INTEGER)
			if (se->constraints != NULL && se->expr_type != ASN_BASIC_INTEGER) {
				// obtaining lowerbound
				long lowerbound;
				lowerbound = get_lowerbound(se->constraints);
				if (lowerbound != -1) {
					elem->tags.sizeLB = lowerbound;
				}
				// obtaining upperbound
				long upperbound;
				upperbound = get_upperbound(se->constraints);
				if (upperbound != -1) {
					elem->tags.sizeUB = upperbound;
				}
				int extensibility;
				extensibility = get_extensibility(se->constraints);
				if (extensibility) {
					elem->tags.sizeExt = 1;
				}
			} else if ((se->constraints != NULL && se->expr_type == ASN_BASIC_INTEGER)) {
				// checking if constraints are not NULL and parsing them (this is for INTEGER only)
				// obtaining lowerbound
				long lowerbound;
				lowerbound = get_lowerbound(se->constraints);
				if (lowerbound != -1) {
					elem->tags.valueLB = lowerbound;
				}
				// obtaining upperbound
				long upperbound;
				upperbound = get_upperbound(se->constraints);
				if (upperbound != -1) {
					elem->tags.valueUB = upperbound;
				}
				int extensibility;
				extensibility = get_extensibility(se->constraints);
				if (extensibility) {
					elem->tags.valueExt = 1;
				}
			}

			if (se->expr_type == ASN_BASIC_ENUMERATED) {
				// treating the case of anonymous nested enumerator
				// creating the (enumerator) message first
				// since it is nested enum, name would be message specific
				// ToDo - implement workaround for empty identifier in expr
				char *enum_name = malloc(PROTO_NAME_CHARS + 1); // +1 for the null-terminator
				// in real code you would check for errors in malloc here
				strcpy(enum_name, se->Identifier);
				if (expr->Identifier != NULL) {
					strcat(enum_name, expr->Identifier);
				} else if (strlen(msgdef->name) > 0) {
					strcat(enum_name, msgdef->name);
				} else {
					strcat(enum_name, "Nested");
				}
				// also excluding all dashes from the name
				int j = 0;
//				char *correct_enum_name = malloc(strlen(enum_name) + 1);
				char *correct_enum_name = strdup(enum_name);
				for (int i = 0; i < strlen(enum_name); i++) {
					if (enum_name[i] == '-') {
						// skipping and not appending this char
						continue;
					} else {
						correct_enum_name[j] = enum_name[i];
						j++;
					}
				}

				// cleaning up leftover from the previous string
				for (int k = j; k < strlen(enum_name); k++) {
					correct_enum_name[k] = '\0';
				}


				proto_enum_t *newenum = proto_create_enum(correct_enum_name,
														  "enumerated from %s:%d", se->module->source_file_name, se->_lineno);
				// referencing to the newly created enum and adding a new message element
				strcpy(elem->type, correct_enum_name);
				// freeing memory
//				free(correct_enum_name);
				// processing and adding enumerated
				proto_process_enumerated(se, &newenum);
				proto_enums_add_enum(proto_module, newenum);

				//parsing constraints
				// checking if the structure is extensible
				int isExtensible = 0;
				int elCount = 0;
				parse_constraints_enumerated(se, &elCount, &isExtensible);
				if (elCount != -1) {
					elem->tags.valueUB = elCount;
					elem->tags.valueLB = 0;
				}
				if (isExtensible) {
					elem->tags.valueExt = 1;
				}
			} else if (se->expr_type == ASN_BASIC_REAL) {
				strcpy(elem->type, "float");
			} else if (se->expr_type == ASN_BASIC_BIT_STRING) {
				strcpy(elem->type, "asn1.v1.BitString");
			} else if (se->expr_type == ASN_BASIC_OBJECT_IDENTIFIER) {
				strcpy(elem->type, "BasicOid");
			} else if (se->expr_type == ASN_BASIC_BOOLEAN) {
				strcpy(elem->type, "bool");
			} else if (se->expr_type == ASN_BASIC_OCTET_STRING) {
				strcpy(elem->type, "bytes");
				if (se->constraints != NULL) {
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(se->constraints, APF_BYTES_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						elem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						elem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						elem->tags.sizeUB = upperbound;
					}
					sprintf(elem->rules, "bytes = {%s}", constraint);
					free(constraint);
				}
			} else if (se->expr_type == ASN_STRING_UTF8String ||
					   se->expr_type == ASN_STRING_PrintableString ||
					   se->expr_type == ASN_STRING_TeletexString) {
				strcpy(elem->type, "string");
				if (se->constraints != NULL) {
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(se->constraints, APF_STRING_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						elem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						elem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						elem->tags.sizeUB = upperbound;
					}
					sprintf(elem->rules, "string = {%s}", constraint);
					free(constraint);
				}
			} else if (se->meta_type == AMT_TYPE && se->expr_type == ASN_CONSTR_SEQUENCE_OF) {
				elem->tags.repeated = 1;
				if (se->constraints != NULL) {
					long lowerbound = -1;
					long upperbound = -1;
					int extensibility = 0;
					char *constraint = proto_constraint_print(se->constraints, APF_REPEATED_VALUE, &lowerbound,
															  &upperbound, &extensibility);
					if (extensibility) {
						elem->tags.sizeExt = 1;
					}
					if (lowerbound != -1) {
						elem->tags.sizeLB = lowerbound;
					}
					if (upperbound != -1) {
						elem->tags.sizeUB = upperbound;
					}
					sprintf(elem->rules, "repeated = {%s}", constraint);
					free(constraint);
				}
				se2 = TQ_FIRST(&se->members); // Find the type
				if (se2->expr_type == A1TC_REFERENCE && se2->meta_type == AMT_TYPEREF) {
					if (se2->reference->comp_count == 1) {
						struct asn1p_ref_component_s *comp = se2->reference->components;
						strcpy(elem->type, comp->name);
					}
				} else {
					// Could Sequence OF refer directly to Sequence OF?
					if ((se2->constraints != NULL && se2->expr_type == ASN_BASIC_INTEGER)) {
						// obtaining lowerbound
						long lowerbound;
						lowerbound = get_lowerbound(se2->constraints);
						if (lowerbound != -1) {
							elem->tags.valueLB = lowerbound;
						}
						// obtaining upperbound
						long upperbound;
						upperbound = get_upperbound(se2->constraints);
						if (upperbound != -1) {
							elem->tags.valueUB = upperbound;
						}
						int extensibility;
						extensibility = get_extensibility(se2->constraints);
						if (extensibility) {
							elem->tags.valueExt = 1;
						}
					} else if (se2->expr_type == ASN_BASIC_BIT_STRING) {
						strcpy(elem->type, "asn1.v1.BitString");
					} else if (se2->expr_type == ASN_BASIC_OBJECT_IDENTIFIER) {
						strcpy(elem->type, "BasicOid");
					} else if (se2->expr_type == ASN_BASIC_BOOLEAN) {
						strcpy(elem->type, "bool");
					} else if (se2->expr_type == ASN_BASIC_OCTET_STRING) {
						strcpy(elem->type, "bytes");
						if (se2->constraints != NULL) {
							long lowerbound = -1;
							long upperbound = -1;
							int extensibility = 0;
							char *constraint = proto_constraint_print(se2->constraints, APF_BYTES_VALUE, &lowerbound,
																	  &upperbound, &extensibility);
							if (extensibility) {
								elem->tags.sizeExt = 1;
							}
							if (lowerbound != -1) {
								elem->tags.sizeLB = lowerbound;
							}
							if (upperbound != -1) {
								elem->tags.sizeUB = upperbound;
							}
							sprintf(elem->rules, "bytes = {%s}", constraint);
							free(constraint);
						}
					} else if (se2->expr_type == ASN_STRING_UTF8String ||
							   se2->expr_type == ASN_STRING_PrintableString ||
							   se2->expr_type == ASN_STRING_TeletexString) {
						strcpy(elem->type, "string");
						if (se2->constraints != NULL) {
							long lowerbound = -1;
							long upperbound = -1;
							int extensibility = 0;
							char *constraint = proto_constraint_print(se2->constraints, APF_STRING_VALUE, &lowerbound,
																	  &upperbound, &extensibility);
							if (extensibility) {
								elem->tags.sizeExt = 1;
							}
							if (lowerbound != -1) {
								elem->tags.sizeLB = lowerbound;
							}
							if (upperbound != -1) {
								elem->tags.sizeUB = upperbound;
							}
							sprintf(elem->rules, "string = {%s}", constraint);
							free(constraint);
						}
					} else {
						fprintf(stderr, "unhandled expr_type: %d and meta_type: %d in %s:%s \n",
								se->expr_type, se->meta_type, expr->Identifier, se->Identifier);
					}
				}
				if (oneof) {
					char *msgName = malloc(strlen(se->Identifier) + strlen(expr->Identifier) + 1); // +1 for the null-terminator
					// in real code you would check for errors in malloc here
					strcpy(msgName, se->Identifier);
					if (expr->Identifier != NULL) {
						strcat(msgName, expr->Identifier);
					} else if (strlen(msgdef->name) > 0) {
						strcat(msgName, msgdef->name);
					} else {
						strcat(msgName, "Nested");
					}
					proto_msg_t *msg = proto_create_message(msgName, se->spec_index, se->_type_unique_index,
															"repeated from %s:%d", se->module->source_file_name, se->_lineno, 0);
					proto_msg_def_t *elem1 = proto_create_msg_elem(se->Identifier, msgName, NULL);
					strcpy(elem1->rules, elem->rules);
					strcpy(elem1->type, elem->type);
					elem1->tags.sizeExt = elem->tags.sizeExt;
					elem1->tags.valueExt = elem->tags.valueExt;
					elem1->tags.sizeLB = elem->tags.sizeLB;
					elem1->tags.sizeUB = elem->tags.sizeUB;
					elem1->tags.valueLB = elem->tags.valueLB;
					elem1->tags.valueUB = elem->tags.valueUB;
					elem1->tags.repeated = elem->tags.repeated;

					proto_msg_add_elem(msg, elem1);
					proto_messages_add_msg(proto_module, msg);

					strcpy(elem->rules, "");
					elem->tags.sizeExt = 0;
					elem->tags.valueExt = 0;
					elem->tags.sizeLB = -1;
					elem->tags.sizeUB = -1;
					elem->tags.valueLB = -1;
					elem->tags.valueUB = -1;
					elem->tags.repeated = 0;
					strcpy(elem->type, msgName);
				}
// TODO: Finish this so that it works on 41-int-optional
//			} else if (se->meta_type == AMT_TYPE && se->expr_type == ASN_CONSTR_SEQUENCE) {
//				if (se->constraints != NULL) {
//					char *constraint = proto_constraint_print(se->constraints, APF_REPEATED_VALUE);
//					sprintf(elem->rules, "repeated = {%s}", constraint);
//					free(constraint);
//				}
//				se2 = TQ_FIRST(&se->members); // Find the type
//				if (se2->expr_type == A1TC_REFERENCE && se2->meta_type == AMT_TYPEREF) {
//					if (se2->reference->comp_count == 1) {
//						struct asn1p_ref_component_s *comp = se2->reference->components;
//						strcpy(elem->type, comp->name);
//					}
//				} else if (se2->meta_type == AMT_TYPE) {
//					proto_process_children(se, msgdef, 0, 0, asntree, NULL);
//					fprintf(stderr, "recursing expr_type: %d and meta_type: %d in %s:%s \n",
//							se2->expr_type, se2->meta_type, se->Identifier, se2->Identifier);
//				} else {
//					fprintf(stderr, "unhandled expr_type: %d and meta_type: %d in %s:%s \n",
//							se->expr_type, se->meta_type, expr->Identifier, se->Identifier);
//				}
			} else if (se->expr_type == A1TC_REFERENCE && se->meta_type == AMT_TYPEREF) {
				// Some basic parsing first
				if (se->constraints &&
					se->constraints->type == ACT_CA_SET) {
					if (se->constraints->el_count == 1) {
						asn1p_constraint_t *el0 = se->constraints->elements[0];
						if (el0->type == ACT_CA_CRC) {
							for (int ct = 0; ct < (int) el0->el_count; ct++) {
								asn1p_constraint_t *el00 = el0->elements[ct];
								if (el00->type == ACT_EL_VALUE && el00->value->type == ATV_REFERENCED) {
									asn1p_ref_t *objectSetRef = el00->value->value.reference;
									strcpy(elem->type, objectSetRef->components[0].name);
								} else if (el00->type == ACT_EL_VALUE && el00->value->type == ATV_VALUESET) {
									asn1p_constraint_t *valueSetConst = el00->value->value.constraint;
									strcpy(elem->type, asn1f_printable_value(valueSetConst->containedSubtype));
								} else {
									fprintf(stderr, "Unexpected constraint type: %d or value type %d\n",
											el00->type, el00->value->type);
									return -1;
								}
							}
						} else {
							fprintf(stderr, "expected CA_CRC constraint. Got: %d of %s:%s\n",
									el0->type, expr->Identifier, se->Identifier);
							return -1;
						}
					} else {
						fprintf(stderr, "Unexpected number of constraints in CA_SET: %d\n",
								se->combined_constraints->el_count);
						return -1;
					}
				} else {
					struct asn1p_ref_component_s *comp = se->reference->components;
					if (se->reference->comp_count == 2) {
						sprintf(elem->type, "%s", (comp + 1)->name);
					} else if (se->reference->comp_count == 1) {
						strcpy(elem->type, comp->name);
					}
				}

				// checking if the structure is extensible
				int isExtensible = 0;
				int oneofDependent = 0;
                isExtensible = structure_is_extensible(asn, se->reference->components->name, &oneofDependent);
				if (isExtensible == 1 && oneofDependent == 0) {
					elem->tags.valueExt = 1;
				} else if (isExtensible == 1 && oneofDependent == 1) {
					elem->tags.choiceExt = 1;
				}

				// make sure that the type is enumerator
				int enm = 0;
				int elCount = -1;
                enm = is_enum(asn, se->reference->components->name, &elCount);
				if (enm) {
					if (elCount != -1) {
						elem->tags.valueUB = elCount;
					}
					elem->tags.valueLB = 0;
				}

				// checking whether item refers to the other structure
				if (se->rhs_pspecs != NULL) {
					asn1p_expr_t *innerSe;
					char *referencedStructName = NULL;
					if (TQ_FIRST(&se->rhs_pspecs->members)) {
						TQ_FOR(innerSe, &(se->rhs_pspecs->members), next)
						{
							if (innerSe->constraints != NULL) {
								if (innerSe->constraints->containedSubtype != NULL) {
									if (innerSe->constraints->containedSubtype->type == ATV_TYPE) {
											if (innerSe->constraints->containedSubtype->value.v_type->expr_type == A1TC_REFERENCE &&
												innerSe->constraints->containedSubtype->value.v_type->reference != NULL) {
													// extracting the name of the referenced type here
													referencedStructName = innerSe->constraints->containedSubtype->value.v_type->reference->components->name;
											}
										}
								}
							}
						}
					}
					// take skeleton of referenced type and implement it to this element
					if (referencedStructName != NULL) {
						strcpy(elem->type, referencedStructName);
						// expr_type != ASN_CONSTR_SEQUENCE_OF is to avoid some specific case in *AP definitions by O-RAN and 3GPP
						if (expr->expr_type != ASN_CONSTR_SEQUENCE_OF) {
							fprintf(stderr, "proto_process_children() - line 1964: processing message %s, children %s and "
											"trying to find its reference %s\n", expr->Identifier, se->Identifier,
									referencedStructName);
							// Searching for referenced type in ASN.1 tree and adjusting element of the message
							//  (parsing constraints). Also, extracting constraints (referenced type, which defines
							//  shape of a nested message)
							char *refType = se->reference->components->name;
							// find referenced type and process it as element
							char constrainedType[PROTO_NAME_CHARS] = {};
							int matched = 0;
							find_and_process_referenced_type(refType, asn, elem, proto_module,
															 constrainedType, &matched);
							if (matched > 0 && strlen(constrainedType) > 0) {
								fprintf(stderr,
										"proto_process_children() - line 1975: extracted constrained type %s for %s\n",
										constrainedType, refType);
							} else {
								fprintf(stderr,
										"proto_process_children() - line 1980: constrained type was NOT found for %s, strlen is %ld\n",
										refType, strlen(constrainedType));
							}
							// Extracting constrained message and creating it
							asn1p_expr_t *refMsg = malloc(sizeof(*se));
							// We assume by default that the refMsg would be found, because we have referencedStructName
							int found = 0;
							found = find_and_get_referenced_message(asn, refMsg, referencedStructName);
							if (found == 0) {
								fprintf(stderr,
										"proto_process_children() - line 1986: referenced message %s was not found in the tree\n",
										referencedStructName);
							} else {
								// ToDo - add just created message to the list of messages, which were created in
								//  order to exclude it from the future processing (helps to save processing time and avoid
								//  message duplicates)
								fprintf(stderr,
										"proto_process_children() - line 2007: Processing children %s for structure %s with referenced message %s\n",
										se->Identifier, expr->Identifier, refMsg->Identifier);
								// ToDo - check if referenced message was already created.. If not, then create it..
								int ret = 0;
								if (strlen(constrainedType) > 0) {
									asn1p_expr_t *constrainedSkeleton = malloc(sizeof(*se));
									int result = find_and_get_referenced_message(asn, constrainedSkeleton,
																				 constrainedType);
									fprintf(stderr, "proto_process_children() - line 2014: Constrained skeleton is %s\n",
											constrainedSkeleton->Identifier);
									if (refMsg->meta_type == AMT_VALUESET) {
										if (result != 0) {
											ret = process_class_referenced_message(refMsg, proto_module, asn, 1,
																				   constrainedSkeleton);
										} else {
											ret = process_class_referenced_message(refMsg, proto_module, asn, 1,
																				   NULL);
										}
									} else {
										ret = process_class_referenced_message(refMsg, proto_module, asn, 0,
																			   constrainedSkeleton);
									}
									// ToDo - exclude this message from further processing..
								} else {
									if (refMsg->meta_type == AMT_VALUESET) {
										ret = process_class_referenced_message(refMsg, proto_module, asn, 1,
																			   NULL);
									} else {
										ret = process_class_referenced_message(refMsg, proto_module, asn, 0,
																			   NULL);
									}
									// ToDo - exclude this message from further processing..
								}
								if (ret != 0) {
									printf("Error in proto_process_children() - couldn't process class referenced message (constrained by other class))\n");
									return ret;
								}
							}
						}
					}
				}

			} else if (se->expr_type == ASN_CONSTR_SEQUENCE && se->meta_type == AMT_TYPE) {
				// treating the case of nested SEQUENCE
				char *msgName = malloc(PROTO_NAME_CHARS + 1);
				if (se->Identifier != NULL) {
//					*msgName = malloc(
//							strlen(se->Identifier) + strlen(expr->Identifier) + 1); // +1 for the null-terminator
					// in real code you would check for errors in malloc here
					strcpy(msgName, se->Identifier);
					strcat(msgName, expr->Identifier);
				} else {
//					*msgName = malloc(
//							strlen("Nested") + strlen(expr->Identifier) + 1);
					strcpy(msgName, "Nested");
					strcat(msgName, expr->Identifier);
				}

				proto_msg_t *msg = proto_create_message(msgName, se->spec_index, se->_type_unique_index,
														"sequence from %s:%d", se->module->source_file_name, se->_lineno, 0);

				// referring to the newly created message
				strcpy(elem->type, msgName);
				// freeing memory
//				free(msgName);

				if (se->lhs_params != NULL) {
					char *param_comments = proto_extract_params(msg, se);
					strcat(msg->comments, param_comments);
					free(param_comments);
				}

				int extensibility = 0;
				proto_process_children(se, msg, se->expr_type == ASN_CONSTR_SEQUENCE_OF, 0, &extensibility, proto_module, asn);
				if (extensibility) {
					strcat(msg->comments, "\n@inject_tag: aper:\"valueExt\"");
					elem->tags.valueExt = 1;
				}

				proto_messages_add_msg(proto_module, msg);
			} else if (se->expr_type == ASN_CONSTR_CHOICE) {
				// treating the case of nested CHOICE
				char *msgNameOneOf = malloc(PROTO_NAME_CHARS + 1); // +1 for the null-terminator
				// in real code you would check for errors in malloc here
				strcpy(msgNameOneOf, se->Identifier);
				if (expr->Identifier != NULL) {
					strcat(msgNameOneOf, expr->Identifier);
				} else if (strlen(msgdef->name) > 0) {
					strcat(msgNameOneOf, msgdef->name);
				} else {
					strcat(msgNameOneOf, "Nested");
				}
				proto_msg_t *msg = proto_create_message(msgNameOneOf, se->spec_index, se->_type_unique_index,
														"choice from %s:%d", se->module->source_file_name, se->_lineno, 0);
				if (se->lhs_params != NULL) {
					char *param_comments = proto_extract_params(msg, se);
					strcat(msg->comments, param_comments);
					free(param_comments);
				}

				proto_msg_oneof_t *oneof = proto_create_msg_oneof(msgNameOneOf,
																  "choice from %s:%d", se->module->source_file_name, se->_lineno);
				// referring to the newly created message
				strcpy(elem->type, msgNameOneOf);
				// freeing memory
//				free(msgNameOneOf);
				proto_msg_add_oneof(msg, oneof);

				int extensibility = 0;
				proto_process_children(se, (proto_msg_t *) oneof, 0, 1, &extensibility, proto_module, asn);

				if (extensibility) {
					strcat(msg->comments, "\n@inject_tag: aper:\"choiceExt\"");
					elem->tags.choiceExt = 1;
				}

				proto_messages_add_msg(proto_module, msg);
			} else if (se->expr_type == A1TC_UNIVERVAL) { // for enum values
				continue;
			} else {
				// fprintf(stderr, "Unexpected type %d %d\n", se->expr_type, se->meta_type);
			}
			if (se->expr_type == A1TC_EXTENSIBLE) {
				extensible = 1;
				*extensibility = 1;
				if (children == 1 && se->next.tq_next == NULL) {
                    // this is an empty message
					proto_msg_def_t *elem1 = proto_create_msg_elem("value", "google.protobuf.Empty", NULL);
					proto_msg_add_elem(msgdef, elem1);
				}
				continue;
			} else if (se->expr_type == A1TC_REFERENCE) {
			} else if (se->Identifier) {
//				INDENT("%s", se->Identifier);
			} else {
//				safe_printf("UNHANDLED %s", se->expr_type);
			}
			proto_msg_add_elem(msgdef, elem);
//			safe_printf(" = %d;\n", ++index);
		}
		if (extensible) {
//			INDENT("// Extensible\n");
		}
	}

	return 0;
}

static char *
proto_constraint_print(const asn1p_constraint_t *ct, enum asn1print_flags2 flags, long *lowerbound, long *upperbound,
					   int *extensibility) {
	int symno = 0;
	int perhaps_subconstraints = 0;
	char *result = malloc(1024 * sizeof(char));
	memset(result, 0, 1024);
	char *val = NULL;

	if (ct == 0) return 0;

	switch (ct->type) {
		case ACT_EL_TYPE:
			val = proto_value_print(ct->containedSubtype, (enum asn1print_flags) flags, lowerbound);
			*upperbound = *lowerbound;
			strcat(result, val);
			free(val);
			perhaps_subconstraints = 1;
			break;
		case ACT_EL_VALUE:
			if (flags & APF_STRING_VALUE || flags & APF_BYTES_VALUE) {
				strcat(result, "min_len: ");
				val = proto_value_print(ct->value, (enum asn1print_flags) flags, lowerbound);
				strcat(result, val);
				free(val);
				strcat(result, ", max_len: ");
				val = proto_value_print(ct->value, (enum asn1print_flags) flags, upperbound);
				strcat(result, val);
				free(val);
				break;
			} else if (flags & APF_REPEATED_VALUE) {
				strcat(result, "min_items: ");
				val = proto_value_print(ct->value, (enum asn1print_flags) flags, lowerbound);
				strcat(result, val);
				free(val);
				strcat(result, ", max_items: ");
				val = proto_value_print(ct->value, (enum asn1print_flags) flags, upperbound);
				strcat(result, val);
				free(val);
				break;
			}
			val = proto_value_print(ct->value, (enum asn1print_flags) flags, lowerbound);
			*upperbound = *lowerbound;
			strcat(result, val);
			free(val);
			perhaps_subconstraints = 1;
			break;
		case ACT_EL_RANGE:
		case ACT_EL_LLRANGE:
		case ACT_EL_RLRANGE:
		case ACT_EL_ULRANGE:
			switch (ct->type) {
				case ACT_EL_RANGE:
				case ACT_EL_RLRANGE:
					if (flags & APF_STRING_VALUE) {
						strcat(result, "min_len: ");
					} else if (flags & APF_REPEATED_VALUE) {
						strcat(result, "min_items: ");
					} else if (flags & APF_BYTES_VALUE) {
						strcat(result, "min_len: ");
					} else {
						strcat(result, "gte: ");
					}
					break;
				case ACT_EL_LLRANGE:
				case ACT_EL_ULRANGE:
					if (flags & APF_STRING_VALUE) {
						strcat(result, "min_len: ");
					} else if (flags & APF_REPEATED_VALUE) {
						strcat(result, "min_items: ");
					} else if (flags & APF_BYTES_VALUE) {
						strcat(result, "min_len: ");
					} else {
						strcat(result, "gt: ");
					}
					break;
				default:
					strcat(result, "?..?");
					break;
			}
			val = proto_value_print(ct->range_start, (enum asn1print_flags) flags, lowerbound);
			strcat(result, val);
			free(val);

			val = proto_value_print(ct->range_stop, (enum asn1print_flags) flags, upperbound);
			if (strlen(val) == 0) {
				free(val);
				break;
			} else {
				strcat(result, ", ");
			}
			switch (ct->type) {
				case ACT_EL_RANGE:
				case ACT_EL_LLRANGE:
					if (flags & APF_STRING_VALUE) {
						strcat(result, "max_len: ");
					} else if (flags & APF_REPEATED_VALUE) {
						strcat(result, "max_items: ");
					} else if (flags & APF_BYTES_VALUE) {
						strcat(result, "max_len: ");
					} else {
						strcat(result, "lte: ");
					}
					break;
				case ACT_EL_RLRANGE:
				case ACT_EL_ULRANGE:
					if (flags & APF_STRING_VALUE) {
						strcat(result, "max_len: ");
					} else if (flags & APF_STRING_VALUE) {
						strcat(result, "max_items: ");
					} else if (flags & APF_BYTES_VALUE) {
						strcat(result, "max_len: ");
					} else {
						strcat(result, "lt: ");
					}
					break;
				default:
					strcat(result, "?..?");
					break;
			}
			strcat(result, val);
			free(val);
			break;
		case ACT_EL_EXT:
			// this is to parse extension flag
			*extensibility = 1;
			break;
		case ACT_CT_SIZE:
		case ACT_CT_FROM:
			switch (ct->type) {
				case ACT_CT_SIZE:
					break;
				case ACT_CT_FROM:
					strcat(result, "FROM");
					break;
				default:
					strcat(result, "??? ");
					break;
			}
			assert(ct->el_count != 0);
			assert(ct->el_count == 1);
			char *add = proto_constraint_print(ct->elements[0], flags, lowerbound, upperbound, extensibility);
			strcat(result, add);
			free(add);
			break;
		case ACT_CT_WCOMP:
			assert(ct->el_count != 0);
			assert(ct->el_count == 1);
			strcat(result, "WITH COMPONENT");
			perhaps_subconstraints = 1;
			break;
		case ACT_CT_WCOMPS: {
			unsigned int i;
			strcat(result, "WITH COMPONENTS { ");
			for (i = 0; i < ct->el_count; i++) {
				asn1p_constraint_t *cel = ct->elements[i];
				if (i) strcat(result, ", ");
				char *add = proto_constraint_print(cel, flags, lowerbound, upperbound, extensibility);
				strcat(result, add);
				free(add);
				switch (cel->presence) {
					case ACPRES_DEFAULT:
						break;
					case ACPRES_PRESENT:
//					safe_printf(" PRESENT");
						break;
					case ACPRES_ABSENT:
//					safe_printf(" ABSENT");
						break;
					case ACPRES_OPTIONAL:
//					safe_printf(" OPTIONAL");
						break;
				}
			}
			strcat(result, " }");
		}
			break;
		case ACT_CT_CTDBY:
			strcat(result, "CONSTRAINED BY ");
			assert(ct->value->type == ATV_UNPARSED);
			safe_fwrite(ct->value->value.string.buf, ct->value->value.string.size);
			break;
		case ACT_CT_CTNG:
			strcat(result, "CONTAINING ");
			asn1print_expr(ct->value->value.v_type->module->asn1p,
						   ct->value->value.v_type->module,
						   ct->value->value.v_type,
						   (enum asn1print_flags) flags, 1);
			break;
		case ACT_CT_PATTERN:
			strcat(result, "PATTERN ");
			asn1print_value(ct->value, (enum asn1print_flags) flags);
			break;
		case ACT_CA_SET:
			symno++;   /* Fall through */
		case ACT_CA_CRC:
			symno++;   /* Fall through */
		case ACT_CA_CSV:
			symno++;   /* Fall through */
		case ACT_CA_UNI:
			symno++;   /* Fall through */
		case ACT_CA_INT:
			symno++;   /* Fall through */
		case ACT_CA_EXC: {
			char *symtable[] = {" EXCEPT ", " ^ ", ",",
								"", "("};
			unsigned int i;
//            if(ct->type == ACT_CA_SET) safe_printf("{");
			for (i = 0; i < ct->el_count; i++) {
				if (i) strcat(result, symtable[symno]);
				if (ct->type == ACT_CA_CRC) strcat(result, "{");
				char *add = proto_constraint_print(ct->elements[i], flags, lowerbound, upperbound, extensibility);
				strcat(result, add);
				free(add);
				if (ct->type == ACT_CA_CRC) strcat(result, "}");
				if (ct->type == ACT_CA_SET && i + 1 < ct->el_count)
					strcat(result, "} ");
			}
//            if(ct->type == ACT_CA_SET) safe_printf("}");
		}
			break;
		case ACT_CA_AEX:
			assert(ct->el_count == 1);
			strcat(result, "ALL EXCEPT");
			perhaps_subconstraints = 1;
			break;
		case ACT_INVALID:
			assert(ct->type != ACT_INVALID);
			break;
	}

	if (perhaps_subconstraints && ct->el_count) {
		strcat(result, " ");
		assert(ct->el_count == 1);
		char *add = proto_constraint_print(ct->elements[0], flags, lowerbound, upperbound, extensibility);
		strcat(result, add);
		free(add);
	}

	return result;
}

// This function creates a message for a standalone message defined through the CLASS
// role of constrainedSkeleton is following - it limits fields of the CLASS to be included to the messages,
// i.e., some of the CLASS fields would not be included in the final message
static int
process_class_referenced_message(asn1p_expr_t *expr, proto_module_t *proto_module, asn1p_t *asntree, int isValueSet, asn1p_expr_t *constrainedSkeleton) {
	char comment[PROTO_COMMENTS_CHARS] = {};
	char msgname[PROTO_NAME_CHARS] = {};

	fprintf(stderr, "process_class_referenced_message(): Processing structure %s\n", expr->Identifier);

	if (constrainedSkeleton != NULL) {
		fprintf(stderr, "process_class_referenced_message(): Constrained skeleton is NOT NULL! Value Set is %d\n", isValueSet);
	}

	strcpy(comment, "concrete instance(s) of class ");
	if (expr->reference != NULL && expr->reference->comp_count > 0) {
		strcat(comment, expr->reference->components->name);
	}
	strcat(comment, " from \%s:\%d");
	strcat(msgname, expr->Identifier);

	proto_msg_t *msg = proto_create_message(msgname, expr->spec_index, expr->_type_unique_index, comment,
											expr->module->source_file_name, expr->_lineno, 0);

    // parsing extensibility
    if (expr->ioc_table->extensible == 1) {
        strcat(msg->comments, "\n@inject_tag: aper:\"valueExt\"");
    }

	// In case we are processing VALUE SET, firstly, search if any other message has
	// the same signature and then reference it. Otherwise, process it as anonymous VALUE SET (the one which
	// has nested definition, same as nested SEQUENCE or nested ENUMERATED)
	if (isValueSet) {
		// defining in case we need to compose a VALUE SET later..
		proto_msg_t *msgOneOf = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
													 "value set from %s:%d", expr->module->source_file_name, expr->_lineno, 0);
		proto_msg_oneof_t *oneof = proto_create_msg_oneof(expr->Identifier,
														  "value set translated as choice from %s:%d", expr->module->source_file_name, expr->_lineno);

		int rowIdx = 0;
		int counter = 0;
		// computing how many referenced structs are inside the VALUE SET
		for (rowIdx = 0; rowIdx < (int) expr->ioc_table->rows; rowIdx++) {
			asn1p_ioc_row_t *table_row = expr->ioc_table->row[rowIdx];

			char *refName = NULL;
			refName = find_referenced_message(expr->reference->components->name, table_row, asntree);

			if (refName != NULL && strcmp(refName, "") != 0) {
				// Found referenced message -> increasing counter
				counter++;
			}
		}

		if (counter == expr->ioc_table->rows) {
			// compose message as a regular choice
			rowIdx = 0;
			for (rowIdx = 0; rowIdx < (int) expr->ioc_table->rows; rowIdx++) {
				asn1p_ioc_row_t *table_row = expr->ioc_table->row[rowIdx];

				char *refName = NULL;
				refName = find_referenced_message(expr->reference->components->name, table_row, asntree);
				proto_msg_def_t *elem = proto_create_msg_elem(refName, refName, NULL);
				proto_msg_add_elem((proto_msg_t *) oneof, elem);
			}
			if ((int) expr->ioc_table->rows > 0) {
				proto_msg_add_oneof(msgOneOf, oneof);
				proto_messages_add_msg(proto_module, msgOneOf);
			} else {
				proto_msg_t *msgEmpty = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index,
															 "value set from %s:%d", expr->module->source_file_name, expr->_lineno, 0);
				proto_msg_def_t *elem = proto_create_msg_elem("value", "google.protobuf.Empty", NULL);
				proto_msg_add_elem(msgEmpty, elem);
				proto_messages_add_msg(proto_module, msgEmpty);
			}
		} else {
			// compose a message as a value set with one item treated as a (canonical) choice
			int unique = 0;
			rowIdx = 0;
			int colIdx = 0;
			// we want to iterate over the CLASS structure itself, function below will return unique presence
			// and name of the part which is treated as choice
			char *choicePart = malloc(PROTO_COMMENTS_CHARS);
			memset(choicePart, 0, PROTO_COMMENTS_CHARS);
			int res = process_referenced_class(expr->reference->components->name, &unique, choicePart, asntree);

			if (res != 0) {
				// now we should.. compose the message structure:
				//  - start with filling in the choice part of the message. It should be put as a separate message
				//  - fill in a skeleton of the main message, where we will include in the main part a choice message..

				// firstly composing choice message
				// verifying if choice part was found in the CLASS definition.
				// If it wasn't, sticking to regular choice message
				if (strcmp("", choicePart) != 0) {
					// choice part was found!
					for (rowIdx = 0; rowIdx < (int) expr->ioc_table->rows; rowIdx++) {
						asn1p_ioc_row_t *table_row = expr->ioc_table->row[rowIdx];
						// get unique index name first, then process type and compose element
                        char *elemName = malloc(PROTO_COMMENTS_CHARS);
                        memset(elemName, 0, PROTO_COMMENTS_CHARS);
                        colIdx = 0;
                        for (colIdx = 0; colIdx < (int) table_row->columns; colIdx++) {
                            struct asn1p_ioc_cell_s colij = table_row->column[colIdx];
                            if (colij.field->unique == 1) {
                                strcpy(elemName, colij.value->Identifier);
                                break;
                            }
                        }
                        // process and compose element
                        colIdx = 0;
						for (colIdx = 0; colIdx < (int) table_row->columns; colIdx++) {
							struct asn1p_ioc_cell_s colij = table_row->column[colIdx];
							if (strcmp(colij.field->Identifier, choicePart) == 0) {
								// ToDo - find a way to parse type of the element..
								// colij.value->Identifier must be present, otherwise anonymous value set can't be defined
								proto_msg_def_t *elem = proto_create_msg_elem(colij.value->Identifier,
																			  colij.value->Identifier, NULL);
                                if (strlen(elemName) > 0) {
                                    strcpy(elem->name, elemName);
                                }
								// parsing extensibility here
								int oneOfDependent = 0;
								int isExtensible = structure_is_extensible(asntree,
																		   colij.value->Identifier,
																		   &oneOfDependent);
								if (isExtensible == 1 && oneOfDependent == 0) {
									elem->tags.valueExt = 1;
								} else if (isExtensible == 1 && oneOfDependent == 1) {
									elem->tags.choiceExt = 1;
								}
								// make sure that the type is enumerator
								int enm = 0;
								int elCount = -1;
								enm = is_enum(asntree, colij.value->Identifier, &elCount);

								if (enm) {
									if (elCount != -1) {
										elem->tags.valueUB = elCount;
									}
									elem->tags.valueLB = 0;
								}

								// We do NOT check whether this field is in the constrained skeleton, because
								// this is not the case. Variable CHOICE part must be present,
								// it doesn't make sense to not include it in the message otherwise.
								proto_msg_add_elem((proto_msg_t *) oneof, elem);
							}
						}
					}
					strcat(msgOneOf->name, choicePart);
					proto_msg_add_oneof(msgOneOf, oneof);
					proto_messages_add_msg(proto_module, msgOneOf);

					// now, when choice is added, composing a value set skeleton
					rowIdx = 0;
					for (rowIdx = 0; rowIdx < (int) expr->ioc_table->rows; rowIdx++) {
						asn1p_ioc_row_t *table_row = expr->ioc_table->row[rowIdx];
						colIdx = 0;
						for (colIdx = 0; colIdx < (int) table_row->columns; colIdx++) {
							struct asn1p_ioc_cell_s colij = table_row->column[colIdx];
							if (strcmp(colij.field->Identifier, choicePart) == 0) {
								// adding our new choice here
								proto_msg_def_t *elem = proto_create_msg_elem(colij.field->Identifier,
																			  msgOneOf->name, NULL);
								if (unique) {
									elem->tags.canonicalOrder = 1;
								}
								// we don't check if this element is in constrainedSkeleton on purpose,
								// because it doesn't make sense to not include variable choice part in the message
								proto_msg_add_elem(msg, elem);
							} else {
								proto_msg_def_t *elem = proto_create_msg_elem(colij.field->Identifier,
																			  colij.value->reference->components->name, NULL);
								// parsing extensibility here
								int oneOfDependent = 0;
								int isExtensible = structure_is_extensible(asntree,
																		   colij.value->reference->components->name,
																		   &oneOfDependent);
								if (isExtensible == 1 && oneOfDependent == 0) {
									elem->tags.valueExt = 1;
								} else if (isExtensible == 1 && oneOfDependent == 1) {
									elem->tags.choiceExt = 1;
								}
								// make sure that the type is enumerator
								int enm = 0;
								int elCount = -1;
								enm = is_enum(asntree, colij.value->reference->components->name, &elCount);

								if (enm) {
									if (elCount != -1) {
										elem->tags.valueUB = elCount;
									}
									elem->tags.valueLB = 0;
								}

								// checking whether there is a unique field
								if (colij.field->unique) {
									elem->tags.unique = 1;
								}

								// check whether this field is in the constrained skeleton
								if (constrainedSkeleton != NULL) {
									asn1p_expr_t *inSe;
									if (TQ_FIRST(&constrainedSkeleton->members)) {
										TQ_FOR(inSe, &(constrainedSkeleton->members), next)
										{
											// each field should be referenced
											if (inSe->reference != NULL && inSe->expr_type == A1TC_REFERENCE) {
												int match = 0;
												for (int k = 0; k < (int) inSe->reference->comp_count; k++) {
													fprintf(stderr, "Reference %d is following: %s\n", k,
															inSe->reference->components[k].name);
													// we should match, whether one of the fields is referenced here.
													// if yes, then add it to the message
													if (strcmp(colij.field->Identifier, inSe->reference->components[k].name) == 0) {
														match++;
													}
												}
												// If field was matched, then add it as a message element
												if (match > 0) {
													proto_msg_add_elem(msg, elem);
													fprintf(stderr, "(CONSTRAINED) Element %s being added to the message %s\n", elem->name, msg->name);
												}
											} else {
												fprintf(stderr, "Field %s of structure %s is not referenced here\n", inSe->Identifier, constrainedSkeleton->Identifier);
											}
										}
									}
								} else {
									proto_msg_add_elem(msg, elem);
								}
							}
						}
						// one iteration is enough - VALUE SET is defined through the same CLASS, and
						// CLASS fields are all the same
						break;
					}
				} else {
					// choice part was not found, composing regular choice message
					for (rowIdx = 0; rowIdx < (int) expr->ioc_table->rows; rowIdx++) {
						asn1p_ioc_row_t *table_row = expr->ioc_table->row[rowIdx];
						colIdx = 0;
						char *refName = NULL;
						refName = find_referenced_message(expr->reference->components->name, table_row, asntree);

						if (refName != NULL && strcmp(refName, "") != 0) {
							// Found referenced message -> adding it as an element.
							// The message itself would be composed later
							proto_msg_def_t *elem = proto_create_msg_elem(refName,
																		  refName, NULL);
							proto_msg_add_elem((proto_msg_t *) oneof, elem);
						} else {
							// no reference message was found. Composing nested message
							proto_msg_t *nestedMsg = proto_create_message(expr->Identifier, expr->spec_index, expr->_type_unique_index, comment,
																		  expr->module->source_file_name, expr->_lineno, 0);
							sprintf(nestedMsg->name, "%s%03d", expr->Identifier, rowIdx);

							colIdx = 0;
							for (colIdx = 0; colIdx < (int) table_row->columns; colIdx++) {
								struct asn1p_ioc_cell_s colij = table_row->column[colIdx];

								proto_msg_def_t *elem = proto_create_msg_elem(colij.field->Identifier, "int32", NULL);
								if (colij.value != NULL) {
									if (colij.value->reference != NULL) {
										strcpy(elem->type, colij.value->reference->components->name);
										// parsing extensibility here
										int oneOfDependent = 0;
										int isExtensible = structure_is_extensible(asntree, colij.value->reference->components->name,
																				   &oneOfDependent);
										if (isExtensible == 1 && oneOfDependent == 0) {
											elem->tags.valueExt = 1;
										} else if (isExtensible == 1 && oneOfDependent == 1) {
											elem->tags.choiceExt = 1;
										}
										// make sure that the type is enumerator
										int enm = 0;
										int elCount = -1;
										enm = is_enum(asntree, colij.value->reference->components->name, &elCount);

										if (enm) {
											if (elCount != -1) {
												elem->tags.valueUB = elCount;
											}
											elem->tags.valueLB = 0;
										}
									} else {
										long lb = -1;
										long ub = -1;
										if (colij.value->meta_type == AMT_VALUE) {
											if (colij.field->members.tq_head != NULL) {
												if (colij.field->members.tq_head->constraints != NULL) {
													lb = get_lowerbound(colij.field->members.tq_head->constraints);
													ub = get_upperbound(colij.field->members.tq_head->constraints);
												}
											}
										}

										if (colij.value->expr_type == ASN_STRING_IA5String ||
											colij.value->expr_type == ASN_STRING_BMPString ||
											colij.value->expr_type == ASN_STRING_PrintableString) {
											strcpy(elem->type, "string");
											if (lb != -1) {
												elem->tags.sizeLB = lb;
											}
											if (ub != -1) {
												elem->tags.sizeUB = ub;
											}
										} else if (colij.value->expr_type == ASN_BASIC_BOOLEAN) {
											strcpy(elem->type, "bool");
										} else if (colij.value->expr_type == ASN_BASIC_BIT_STRING) {
											strcpy(elem->type, "asn1.v1.BitString");
											if (lb != -1) {
												elem->tags.sizeLB = lb;
											}
											if (ub != -1) {
												elem->tags.sizeUB = ub;
											}
										} else if (colij.value->expr_type == ASN_BASIC_OCTET_STRING) {
											strcpy(elem->type, "bytes");
											if (lb != -1) {
												elem->tags.sizeLB = lb;
											}
											if (ub != -1) {
												elem->tags.sizeUB = ub;
											}
										} else if (colij.value->expr_type == ASN_BASIC_REAL) {
											strcpy(elem->type, "float");
										} else if (colij.value->expr_type == ASN_BASIC_INTEGER) {
											if (lb != -1) {
												elem->tags.valueLB = lb;
											}
											if (ub != -1) {
												elem->tags.valueUB = ub;
											}
										}
										// Extensibility and LB and UB (for strings, integers and bytes)
										// is possible to get from field->members->tq_head->constraints->elements
										if (colij.value->meta_type == AMT_VALUE && colij.value->value != NULL) {
											char rules[PROTO_RULES_CHARS] = {};
											const char *pval = asn1f_printable_value(colij.value->value);
											switch (colij.value->value->type) {
												case ATV_INTEGER:
													if ((long) (colij.value->value->value.v_integer) > 2147483647 ||
														(long) (colij.value->value->value.v_integer) < -2147483647) {
														snprintf(rules, PROTO_RULES_CHARS, "int64.const = %d",
																 (int) (colij.value->value->value.v_integer));
														strcpy(elem->type, "int64");
													} else {
														snprintf(rules, PROTO_RULES_CHARS, "int32.const = %d",
																 (int) (colij.value->value->value.v_integer));
													}
													break;
												case ATV_STRING:
												case ATV_UNPARSED:
													snprintf(rules, PROTO_RULES_CHARS, "string.const = '%s'", pval);
													break;
												default:
													fprintf(stderr, "Unhandled value type %d %s\n", colij.value->value->type, pval);
													break;
											}
											strcpy(elem->rules, rules);
										}
									}
								}
								if (colij.field->unique) {
									elem->tags.unique = 1;
								}
								if (colij.field->marker.flags == EM_OPTIONAL) {
									elem->tags.optional = 1;
								}
								proto_msg_add_elem(nestedMsg, elem);
							}
							proto_messages_add_msg(proto_module, nestedMsg);
							proto_msg_def_t *elem = proto_create_msg_elem(nestedMsg->name,
																		  nestedMsg->name, NULL);
							proto_msg_add_elem((proto_msg_t *) oneof, elem);

						}
					}
					proto_msg_add_oneof(msgOneOf, oneof);
					proto_messages_add_msg(proto_module, msgOneOf);
				}
			} else {
				fprintf(stderr, "Processing referenced CLASS %s was not successful, message %s wouldn't be created..\n", expr->reference->components->name, expr->Identifier);
			}
		}
		proto_messages_add_msg(proto_module, msg);
	} else {
		int rowIdx = 0;
		int colIdx = 0;
		for (rowIdx = 0; rowIdx < (int) expr->ioc_table->rows; rowIdx++) {
			asn1p_ioc_row_t *table_row = expr->ioc_table->row[rowIdx];

			for (colIdx = 0; colIdx < (int) table_row->columns; colIdx++) {
				struct asn1p_ioc_cell_s colij = table_row->column[colIdx];

				proto_msg_def_t *elem = proto_create_msg_elem(colij.field->Identifier, "int32", NULL);
				if (colij.value != NULL) {
					if (colij.value->reference != NULL) {
						strcpy(elem->type, colij.value->reference->components->name);
						// parsing extensibility here
						int oneOfDependent = 0;
						int isExtensible = structure_is_extensible(asntree, colij.value->reference->components->name,
																   &oneOfDependent);
						if (isExtensible == 1 && oneOfDependent == 0) {
							elem->tags.valueExt = 1;
						} else if (isExtensible == 1 && oneOfDependent == 1) {
							elem->tags.choiceExt = 1;
						}
						// make sure that the type is enumerator
						int enm = 0;
						int elCount = -1;
						enm = is_enum(asntree, colij.value->reference->components->name, &elCount);

						if (enm) {
							if (elCount != -1) {
								elem->tags.valueUB = elCount;
							}
							elem->tags.valueLB = 0;
						}
					} else {
						// What is the difference in handling of AMT_VALUE vs AMT_TYPE?
						//  - AMT_VALUE is used to indicate that the object in the field is a value, not a type.
						//  In other words, it's a constant.
						//  - AMT_TYPE is used to indicate that the object in the field defined through a type,
						//  e.g., INTEGER, and values of that type may vary.

						long lb = -1;
						long ub = -1;
						if (colij.value->meta_type == AMT_VALUE) {
							if (colij.field->members.tq_head != NULL) {
								if (colij.field->members.tq_head->constraints != NULL) {
									lb = get_lowerbound(colij.field->members.tq_head->constraints);
									ub = get_upperbound(colij.field->members.tq_head->constraints);
								}
							}
						}

						if (colij.value->expr_type == ASN_STRING_IA5String ||
							colij.value->expr_type == ASN_STRING_BMPString ||
							colij.value->expr_type == ASN_STRING_PrintableString) {
							strcpy(elem->type, "string");
							if (lb != -1) {
								elem->tags.sizeLB = lb;
							}
							if (ub != -1) {
								elem->tags.sizeUB = ub;
							}
						} else if (colij.value->expr_type == ASN_BASIC_BOOLEAN) {
							strcpy(elem->type, "bool");
						} else if (colij.value->expr_type == ASN_BASIC_BIT_STRING) {
							strcpy(elem->type, "asn1.v1.BitString");
							if (lb != -1) {
								elem->tags.sizeLB = lb;
							}
							if (ub != -1) {
								elem->tags.sizeUB = ub;
							}
						} else if (colij.value->expr_type == ASN_BASIC_OCTET_STRING) {
							strcpy(elem->type, "bytes");
							if (lb != -1) {
								elem->tags.sizeLB = lb;
							}
							if (ub != -1) {
								elem->tags.sizeUB = ub;
							}
						} else if (colij.value->expr_type == ASN_BASIC_REAL) {
							strcpy(elem->type, "float");
						} else if (colij.value->expr_type == ASN_BASIC_INTEGER) {
							if (lb != -1) {
								elem->tags.valueLB = lb;
							}
							if (ub != -1) {
								elem->tags.valueUB = ub;
							}
						}
						// Extensibility and LB and UB (for strings, integers and bytes)
						// is possible to get from field->members->tq_head->constraints->elements
						if (colij.value->meta_type == AMT_VALUE && colij.value->value != NULL) {
							char rules[PROTO_RULES_CHARS] = {};
							const char *pval = asn1f_printable_value(colij.value->value);
							switch (colij.value->value->type) {
								case ATV_INTEGER:
									if ((long) (colij.value->value->value.v_integer) > 2147483647 ||
										(long) (colij.value->value->value.v_integer) < -2147483647) {
										snprintf(rules, PROTO_RULES_CHARS, "int64.const = %d",
												 (int) (colij.value->value->value.v_integer));
										strcpy(elem->type, "int64");
									} else {
										snprintf(rules, PROTO_RULES_CHARS, "int32.const = %d",
												 (int) (colij.value->value->value.v_integer));
									}
									break;
								case ATV_STRING:
								case ATV_UNPARSED:
									snprintf(rules, PROTO_RULES_CHARS, "string.const = '%s'", pval);
									break;
								default:
									fprintf(stderr, "Unhandled value type %d %s\n", colij.value->value->type, pval);
									break;
							}
							strcpy(elem->rules, rules);
						}
					}
				}

				if (colij.field->unique) {
					elem->tags.unique = 1;
				}
				if (colij.field->marker.flags == EM_OPTIONAL) {
					elem->tags.optional = 1;
				}
				proto_msg_add_elem(msg, elem);
			}
		}
		proto_messages_add_msg(proto_module, msg);
	}

	return 0;
}

static char *
proto_value_print(const asn1p_value_t *val, enum asn1print_flags flags, long *bound) {
	char *result = malloc(256 * sizeof(char));
	memset(result, 0, 256);
	if (val == NULL)
		return result;

	char out[30] = {};

	switch (val->type) {
		case ATV_NOVALUE:
			break;
		case ATV_NULL:
			strcat(result, "NULL");
			return result;
		case ATV_REAL:
			sprintf(out, "%f", val->value.v_double);
			strcat(result, out);
			return result;
		case ATV_TYPE:
			strcat(result, "ERROR not yet implemented");
//		asn1print_expr(val->value.v_type->module->asn1p,
//			val->value.v_type->module,
//			val->value.v_type, flags, 0);
			return result;
		case ATV_INTEGER:
			strcat(result, asn1p_itoa(val->value.v_integer));
			*bound = val->value.v_integer;
			return result;
		case ATV_MIN:
			strcat(result, "0");
			*bound = -2147483647;
			return result;
		case ATV_MAX:
			// no idea why this check is important..
//			if (flags & 0x100) { // APF_INT32_VALUE
			*bound = 2147483647;
			sprintf(out, "%d", INT32_MAX);
			strcat(result, out);
			return result;
//			}
//		safe_printf("MAX"); return 0;
			return result;
		case ATV_FALSE:
			strcat(result, "FALSE");
			return result;
		case ATV_TRUE:
			strcat(result, "TRUE");
			return result;
		case ATV_TUPLE:
			sprintf(out, "{%d, %d}",
					(int) (val->value.v_integer >> 4),
					(int) (val->value.v_integer & 0x0f));
			strcat(result, out);
			return result;
		case ATV_QUADRUPLE:
			sprintf(out, "{%d, %d, %d, %d}",
					(int) ((val->value.v_integer >> 24) & 0xff),
					(int) ((val->value.v_integer >> 16) & 0xff),
					(int) ((val->value.v_integer >> 8) & 0xff),
					(int) ((val->value.v_integer >> 0) & 0xff)
			);
			strcat(result, out);
			return result;
		case ATV_STRING: {
			char *p = (char *) val->value.string.buf;
			strcat(result, "\"");
			if (strchr(p, '"')) {
				/* Mask quotes */
				for (; *p; p++) {
					if (*p == '"') {
						sprintf(out, "%c", *p);
						strcat(result, out);
					}
					sprintf(out, "%c", *p);
					strcat(result, out);
				}
			} else {
				sprintf(out, "%c", *p);
				strcat(result, out);
			}
			strcat(result, "\"");
		}
			return result;
		case ATV_UNPARSED:
			strcat(result, (char *) val->value.string.buf);
			return result;
		case ATV_BITVECTOR: // @suppress("Symbol is not resolved")
		{
			uint8_t *bitvector;
			int bits;
			int i;

			bitvector = val->value.binary_vector.bits;
			bits = val->value.binary_vector.size_in_bits;

			strcat(result, "'");
			if (bits % 8) {
				for (i = 0; i < bits; i++) {
					uint8_t uc;
					uc = bitvector[i >> 3];
					sprintf(out, "%c", ((uc >> (7 - (i % 8))) & 1) ? '1' : '0');
					strcat(result, out);
				}
				strcat(result, "'B");
			} else {
				char hextable[16] = "0123456789ABCDEF";
				for (i = 0; i < (bits >> 3); i++) {
					sprintf(out, "%c", hextable[bitvector[i] >> 4]);
					strcat(result, out);
					sprintf(out, "%c", hextable[bitvector[i] & 0x0f]);
					strcat(result, out);
				}
				strcat(result, "'H");
			}
			return result;
		}
		case ATV_REFERENCED:
			for (size_t cc = 0; cc < val->value.reference->comp_count; cc++) {
				if (cc) strcat(result, ".");
				strcat(result, val->value.reference->components[cc].name);
			}
			break;
		case ATV_VALUESET:
//		return asn1print_constraint(val->value.constraint, flags);
			return result;
		case ATV_CHOICE_IDENTIFIER:
			strcat(result, val->value.choice_identifier.identifier);
			char *val1 = proto_value_print(val->value.choice_identifier.value, flags, bound);
			strcat(result, val1);
			free(val1);
			return result;
	}

	assert(val->type || !"Unknown");

	return result;
}

// this function returns a name of the referenced message, which is defined through CLASS
static char *
find_referenced_message(char *class_name, asn1p_ioc_row_t *referenced_fields, asn1p_t *asn) {

	char *msgname = malloc(PROTO_COMMENTS_CHARS);
	memset(msgname, 0, PROTO_COMMENTS_CHARS);

    asn1p_module_t *mod;
    TQ_FOR(mod, &(asn->modules), mod_next)
    {
        asn1p_expr_t *tc;
        TQ_FOR(tc, &(mod->members), next)
        {
            if (tc->meta_type == AMT_VALUE && tc->expr_type == A1TC_REFERENCE) {
                if (tc->reference != NULL) {
                    if (strcmp(tc->reference->components->name, class_name) == 0) {
                        // found message of the same class
                        if (tc->ioc_table->rows == 1) {
                            asn1p_ioc_row_t *table_row = tc->ioc_table->row[0];

                            if (table_row->columns == referenced_fields->columns) {
                                int match = 0; // to store number of matched fields
                                int colIdx = 0;
                                for (colIdx = 0; colIdx < (int) table_row->columns; colIdx++) {
                                    struct asn1p_ioc_cell_s colij = table_row->column[colIdx];
                                    struct asn1p_ioc_cell_s ref_colij = referenced_fields->column[colIdx];

                                    if (strcmp(colij.field->Identifier, ref_colij.field->Identifier) == 0 &&
                                        colij.field->meta_type == ref_colij.field->meta_type &&
                                        colij.field->expr_type == ref_colij.field->expr_type) {
                                        if (colij.value != NULL && ref_colij.value != NULL) {
                                            if (strcmp(colij.value->Identifier, ref_colij.value->Identifier) == 0 &&
                                                colij.value->meta_type == ref_colij.value->meta_type &&
                                                colij.value->expr_type == ref_colij.value->expr_type) {
                                                match++;
                                            }
                                        } else {
                                            match++;
                                        }
                                    }
                                }
                                if (match == referenced_fields->columns) {
                                    strcat(msgname, tc->Identifier);
                                    return msgname;
                                }
                            }
                        }
                    }
                }
            }
        }
    }


	return msgname;
}
