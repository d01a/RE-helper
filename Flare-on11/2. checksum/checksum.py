# for ( i = 0LL; checksum_len > i; ++i )
#   {
#     decoded_base64_str_1 = decoded_base64_str;
#     inp_Checksum = v15;
#     v18 = ((i * 0x5D1745D1745D1746LL) >> 64) >> 2;
#     v19 = i - 11 * v18;
#     if ( v19 >= 0xB )
#       runtime_panicIndex(v19, i, 11, inp_Checksum, decoded_base64_str_1, 5 * v18, FlareOn2024_char, v12, v13, v23, v24);
#     v10 = byte_4C8035;
#     FlareOn2024_char = byte_4C8035[v19];
#     *(decoded_base64_str_1 + i) = FlareOn2024_char ^ inp_Checksum[i];
#     decoded_base64_str = decoded_base64_str_1;
#     v15 = inp_Checksum;
#   }

import base64

target_b64 = r"cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="
decoded_b64 = base64.b64decode(target_b64)
flare = b"FlareOn2024"
out_ = ""

for i in range(64):
    v18 = ((i * 0x5D1745D1745D1746) >> 64) >> 2
    v19 = i - 11 * v18
    key_chr = flare[v19]
    print(key_chr,decoded_b64[i])
    out_ += chr(key_chr ^ decoded_b64[i])

print(out_)