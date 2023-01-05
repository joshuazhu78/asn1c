# Extracting protobuf from ASN.1

This project adds a `-B` option to output `.proto` files from ASN.1.
This approach generates protobufs like XSD is generated from asn1c.

- [Here](ASN_TO_PROTOBUF_CONVERSION.md) you can read about how various ASN.1 structures are converted to Protobuf structures.
- `-B` option also generates aper tags in output `.proto` file. you can read more about their usage and why it is necessary 
to care about them [here](https://github.com/onosproject/onos-e2-sm/blob/master/docs/encoding_issues-howto.md).
  - These tags are required for enabling `APER` encoding and decoding in Golang with 
[Go APER library](https://github.com/onosproject/onos-lib-go/blob/master/pkg/asn1/aper/README.md).
- Main motivation of introducing `-B` option is to enable a conversion of ASN.1 definitions provided by O-RAN for `E2*` interface 
(i.e., `E2AP` and various `E2SM`s) and enable smooth development in Golang. 
  - You can find a tutorial on how to create 
  your very own E2 Service Model (`E2SM`) [here](https://github.com/onosproject/onos-e2-sm/blob/master/docs/sm-howto.md). 
    - It also includes explanation of the other tooling built around generated Protobuf 
    (i.e., [protoc-gen-choice](https://github.com/onosproject/onos-e2-sm/blob/master/protoc-gen-choice/README.md), 
    [protoc-gen-builder](https://github.com/onosproject/onos-e2-sm/blob/master/protoc-gen-builder/README.md) 
    and [protoc-gen-cgo](https://github.com/onosproject/onos-e2-sm/blob/master/protoc-gen-cgo/README.md) (rudimentary)).

### Here are some examples:
- For a very rudimentary conversion try:
```bash
> ./asn1c/asn1c -B examples/rectangle.asn
////////////////////// rectanglemodulewithconstraints.proto //////////////////////
// Protobuf generated from /rectangle.asn by asn1c-0.9.29
// RectangleModuleWithConstraints

syntax = "proto3";

package examples/rectangle_asn.v1;
option go_package = "examples/rectangle_asn/v1/rectanglemodulewithconstraints;rectanglemodulewithconstraints";

import "validate/v1/validate.proto";
import "asn1/v1/asn1.proto";
import "google/protobuf/empty.proto";

// sequence from rectangle.asn:3
// {Rectangle}
message Rectangle {
    // @inject_tag: aper:"valueLB:0,valueUB:100,"
    int32 height = 1 [ json_name="height"];
    // @inject_tag: aper:"valueLB:0,valueUB:2147483648,"
    int32 width = 2 [ json_name="width"];
};
```

- For something a bit fancier try
```bash
> ./asn1c/asn1c -B tests/tests-asn1c-compiler/58-param-OK.asn1
////////////////////// moduletestparam.proto //////////////////////
// Protobuf generated from /58-param-OK.asn1 by asn1c-0.9.29
// ModuleTestParam { iso org(3) dod(6) internet(1) private(4) enterprise(1) spelio(9363) software(1) asn1c(5) test(1) 58 }

syntax = "proto3";

package tests/tests_c_compiler/58_param_okm.v1;
option go_package = "tests/tests_c_compiler/58_param_okm/v1/moduletestparam;moduletestparam";

import "validate/v1/validate.proto";
import "asn1/v1/asn1.proto";
import "google/protobuf/empty.proto";

// sequence from 58-param-OK.asn1:15
// Param INTEGER:maxSize
// {DirectoryString001}
message DirectoryString001 {
    // choice from 58-param-OK.asn1:15
    oneof directory_string {
        // @inject_tag: aper:"choiceIdx:1,sizeLB:1,sizeUB:128,"
        string teletex_string = 1 [(validate.v1.rules).string = {min_len: 1, max_len: 128}, json_name="teletexString"];
        // @inject_tag: aper:"choiceIdx:2,sizeLB:1,sizeUB:128,"
        string utf8_string = 2 [(validate.v1.rules).string = {min_len: 1, max_len: 128}, json_name="utf8String"];
    }
};

// reference from 58-param-OK.asn1:19
// {DS1}
message Ds1 {
    DirectoryString001 value = 1 [ json_name="value"];
};

// constant Integer from 58-param-OK.asn1:21
// {-}
message Ubname {
    // @inject_tag: aper:"valueLB:128,valueUB:128,"
    int32 value = 1 [(validate.v1.rules).int32.const = 128, json_name="value"];
};
```
