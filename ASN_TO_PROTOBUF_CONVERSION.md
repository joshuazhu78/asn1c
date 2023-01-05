<!--
SPDX-FileCopyrightText: 2022-present Intel Corporation
SPDX-License-Identifier: Apache-2.0
-->

## Some examples of ASN.1 structures to Protobuf structures conversion

### `INTEGER` representation in Protobuf
- Unconstrained integers are represented as an `int32`.
- Constrained integers, depending on the range, are presented either with `int32` or `int64` data types.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/07a-int-OK.asn1
////////////////////// moduletestint1.proto //////////////////////
// Protobuf generated from /07a-int-OK.asn1 by asn1c-0.9.29
// ModuleTestInt1 { iso org(3) dod(6) internet(1) private(4) enterprise(1) spelio(9363) software(1) asn1c(5) test(1) 7 }

syntax = "proto3";

package tests/tests_c_compiler/07a_int_okt.v1;
option go_package = "tests/tests_c_compiler/07a_int_okt/v1/moduletestint1;moduletestint1";

import "validate/v1/validate.proto";
import "asn1/v1/asn1.proto";
import "google/protobuf/empty.proto";

// constant Integer from 07a-int-OK.asn1:14
// {-}
message Int123456 {
    // @inject_tag: aper:"valueLB:123456,valueUB:123456,"
    int32 value = 1 [(validate.v1.rules).int32.const = 123456, json_name="value"];
};

// range of Integer from 07a-int-OK.asn1:16
// {Interval}
message Interval {
    // @inject_tag: aper:"valueLB:-100,valueUB:123456,"
    int32 value = 1 [(validate.v1.rules).int32 = {gte: -100, lte: 123456}, json_name="value"];
};

// range of Integer from 07a-int-OK.asn1:18
// {LongerInterval}
message LongerInterval {
    // @inject_tag: aper:"valueLB:1,valueUB:68719476735,"
    int64 value = 1 [(validate.v1.rules).int64 = {gte: 1, lte: 68719476735}, json_name="value"];
};

// range of Integer from 07a-int-OK.asn1:20
// {SameInterval}
message SameInterval {
    // @inject_tag: aper:"valueLB:6,valueUB:6,"
    int32 value = 1 [(validate.v1.rules).int32 = {in: [1,2,3,4,5,6]}, json_name="value"];
};

// range of Integer from 07a-int-OK.asn1:23
// {Reason}
message Reason {
    int32 value = 1 [ json_name="value"];
};
```

### `ENUMERATED` representation in Protobuf
- Enumerators are represented as an `enum`.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/03-enum-OK.asn1
////////////////////// moduletestenum1.proto //////////////////////
// Protobuf generated from /03-enum-OK.asn1 by asn1c-0.9.29
// ModuleTestEnum1 { iso org(3) dod(6) internet(1) private(4) enterprise(1) spelio(9363) software(1) asn1c(5) test(1) 3 }

syntax = "proto3";

package pkg03_enum_ok.v1;
option go_package = "pkg03_enum_ok/v1/moduletestenum1;moduletestenum1";

import "validate/v1/validate.proto";
import "asn1/v1/asn1.proto";
import "google/protobuf/empty.proto";

// enumerated from 03-enum-OK.asn1:15
enum Enum1 {
    ENUM1_RED = 0;
    ENUM1_GREEN = 1;
    ENUM1_BLUE = 4;
    ENUM1_ALPHA = 5;
};

// enumerated from 03-enum-OK.asn1:23
enum Enum2 {
    ENUM2_RED = 0;
    ENUM2_GREEN = 1;
    ENUM2_BLUE = 45;
    ENUM2_ORANGE = 23;
    ENUM2_ALPHA = 46;
    ENUM2_BETA = 12;
    ENUM2_GAMMA = 103;
};

// enumerated from 03-enum-OK.asn1:33
enum Enum3 {
    ENUM3_A = 0;
    ENUM3_B = 3;
    ENUM3_C = 1;
};

// enumerated from 03-enum-OK.asn1:34
enum Enum4 {
    ENUM4_A = 0;
    ENUM4_B = 1;
    ENUM4_C = 3;
    ENUM4_D = 4;
};

// enumerated from 03-enum-OK.asn1:35
enum Enum5 {
    ENUM5_A = 0;
    ENUM5_Z = 25;
    ENUM5_D = 26;
};
```

### `PrintableString`, `IA5String`, `UTF8String` `BMPString` and `TeletexString` representation in Protobuf
- All of the aforementioned types are represented as a `string`.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/58a-param-OK.asn1
...
// sequence from 58a-param-OK.asn1:15
// Param INTEGER:maxSize
// {DirectoryString001}
message DirectoryString001 {
    // choice from 58a-param-OK.asn1:15
    oneof directory_string {
        // @inject_tag: aper:"choiceIdx:1,sizeLB:1,sizeUB:127,"
        string teletex_string = 1 [(validate.v1.rules).string = {min_len: 1, max_len: 127}, json_name="teletexString"];
        // @inject_tag: aper:"choiceIdx:2,sizeLB:1,sizeUB:127,"
        string utf8_string = 2 [(validate.v1.rules).string = {min_len: 1, max_len: 127}, json_name="utf8String"];
    }
};
...
```

### `OCTET STRING` representation in Protobuf
- Octet string is represented as a byte array, i.e., `[]byte`.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/00a-aper-tags-OK.asn1
...
// range of Integer from 00a-aper-tags-OK.asn1:21
// {Some-Identity}
message SomeIdentity {
    // @inject_tag: aper:"sizeLB:4,sizeUB:4,"
    bytes value = 1 [(validate.v1.rules).bytes = {min_len: 4, max_len: 4}, json_name="value"];
};
...
```

### `BIT STRING` representation in Protobuf
- Bit strings are represented with a custom type, `BitString`, 
defined [here](https://github.com/onosproject/onos-lib-go/blob/master/api/asn1/v1/asn1.proto).
  - It is composed as a `message` with two items:
    - `Value` - defines the `BIT STRING` as a `[]byte` array.
      - All values are aligned from the right with trailing zeroes, 
see example [here](https://github.com/onosproject/onos-e2-sm/blob/0ddfe9a1bf0c7836acfa4dd09d937f30f2513ec5/servicemodels/e2sm_kpm_v2/kpmctypes/BIT_STRING_test.go#L192-L239).
    - `Len` - defines length of a `BIT STRING`, i.e., how many bits are carrying information.
- An example of a `BIT STRING` conversion is here:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/00a-aper-tags-OK.asn1
...
// range of Integer from 00a-aper-tags-OK.asn1:19
// {Some-ID}
message SomeID {
    // @inject_tag: aper:"sizeLB:22,sizeUB:32,"
    asn1.v1.BitString value = 1 [ json_name="value"];
};
...
```

### `SEQUENCE` representation in Protobuf
- `SEQUENCE` is represented as a `message`.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/160-valueExt-OK.asn1
...
// sequence from 160-valueExt-OK.asn1:19
// @inject_tag: aper:"valueExt"
// {T1}
message T1 {
    // @inject_tag: aper:"optional,sizeExt,sizeLB:1,sizeUB:16,"
    repeated ConstrainedString element_list = 1 [(validate.v1.rules).repeated = {min_items: 1, max_items: 16}, json_name="element-List"];
    LongerInterval interval = 2 [ json_name="interval"];
    // @inject_tag: aper:"fromValueExt,"
    ConstrainedString cs = 3 [ json_name="cs"];
};
...
```

### `SEQUENCE OF` representation in Protobuf
- `SEQUENCE OF` is represented as a `repeated` item wrapped in a `message` with only item.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/00a-aper-tags-OK.asn1
...
// sequence from 00a-aper-tags-OK.asn1:15
// @inject_tag: aper:"valueExt"
// {Some-List}
message SomeList {
    // @inject_tag: aper:"optional,sizeLB:1,sizeUB:123456,"
    repeated ConstrainedString element_list = 1 [(validate.v1.rules).repeated = {min_items: 1, max_items: 123456}, json_name="element-List"];
};
...
```

### `CHOICE` representation in Protobuf
- `CHOICE` is represented as a `oneof` message.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/58a-param-OK.asn1
...
// sequence from 58a-param-OK.asn1:15
// Param INTEGER:maxSize
// {DirectoryString001}
message DirectoryString001 {
    // choice from 58a-param-OK.asn1:15
    oneof directory_string {
        // @inject_tag: aper:"choiceIdx:1,sizeLB:1,sizeUB:127,"
        string teletex_string = 1 [(validate.v1.rules).string = {min_len: 1, max_len: 127}, json_name="teletexString"];
        // @inject_tag: aper:"choiceIdx:2,sizeLB:1,sizeUB:127,"
        string utf8_string = 2 [(validate.v1.rules).string = {min_len: 1, max_len: 127}, json_name="utf8String"];
    }
};
...
```

### `VALUE SET` representation in Protobuf
- `VALUE SET` is treated as a `oneof` message.
- An example is:
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/18a-class-OK.asn1
...
// value set from 18a-class-OK.asn1:15
// {Functions}
message Functions {
    // value set translated as choice from 18a-class-OK.asn1:15
    oneof functions {
        // @inject_tag: aper:"choiceIdx:1,"
        Operatorplus operator_plus = 1 [ json_name="operator-plus"];
        // @inject_tag: aper:"choiceIdx:2,"
        Operatorsquare operator_square = 2 [ json_name="operator-square"];
        // @inject_tag: aper:"choiceIdx:3,"
        Operatorroot operator_root = 3 [ json_name="operator-root"];
    }
};
...
```

### `CLASS` representation in Protobuf
`CLASS` is treated as a regular `message` and not included in resulting `.proto`, because it effectively does not define any data structure, 
but instead it is used as an interface, or as a constraint, to define a shape of `VALUE SET` or `SEQUENCE`.


## Why should I care about APER tags in generated Protobuf?
asn1c tool generates APER tags which are a necessary prerequisite to enable APER encoding with
[Go APER library](https://github.com/onosproject/onos-lib-go/blob/master/pkg/asn1/aper/README.md). You can read more 
about the usage of these tags [here](https://github.com/onosproject/onos-e2-sm/blob/master/docs/encoding_issues-howto.md).
