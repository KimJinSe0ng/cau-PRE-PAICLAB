
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_my_ckks()
{
    print_example_banner("Example: My CKKS");

    EncryptionParameters parms(scheme_type::ckks); // 암호화 매개변수 객체를 생성하고, CKKS 스키마를 선택합니다.

    size_t poly_modulus_degree = 16384; // 다항식의 차수를 설정합니다. N=2^14
    parms.set_poly_modulus_degree(poly_modulus_degree); // 암호화 매개변수에 다항식의 차수를 설정합니다.
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 50, 50, 50, 50, 60 })); // 암호화 매개변수에 계수 모듈러스를 설정합니다.
    // CoeffModulus::Create 함수를 사용하여 각 수준의 소수의 비트 크기를 지정합니다. 

    double scale = pow(2.0, 50); // 초기 스케일을 설정합니다. 이 예제에서는 2^40으로 설정됩니다.

    SEALContext context(parms); // 암호 컨텍스트를 생성합니다.
    print_parameters(context); // 암호화 매개변수를 출력합니다.
    cout << endl;

    KeyGenerator keygen(context); // 암호화 키 생성기를 생성합니다.
    auto secret_key = keygen.secret_key(); // 비밀 키를 생성합니다.
    PublicKey public_key;
    keygen.create_public_key(public_key); // 공개 키를 생성합니다.
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // 재선형화 키를 생성합니다.
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys); // Galois 키를 생성합니다.
    Encryptor encryptor(context, public_key); // 암호화 객체를 생성합니다.
    Evaluator evaluator(context); // 평가자 객체를 생성합니다.
    Decryptor decryptor(context, secret_key); // 복호화 객체를 생성합니다.

    CKKSEncoder encoder(context); // CKKSEncoder 객체를 생성합니다.
    size_t slot_count = encoder.slot_count(); // CKKS 스키마의 슬롯 개수를 가져옵니다. 슬롯은 부동 소수점 값의 저장 공간입니다.

    vector<double> input; // 입력 벡터를 저장할 벡터를 생성합니다.
    input.reserve(slot_count); // 벡터 input에 slot_count만큼의 메모리 공간을 미리 예약하는 작업입니다.

    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++) // 입력 벡터를 생성하여 input 벡터에 저장합니다. 이 예제에서는 [0, 1] 범위에서 slot_count 개수의 등간격 점을 생성합니다.
    {
        input.push_back(curr_point); // push_back() 메서드는 벡터의 끝에 요소를 추가하는 역할을 합니다.
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7); // 생성된 입력 벡터를 출력합니다.

    cout << "Evaluating polynomial (x + 1)^2 * (x^2 + 2) ..." << endl;

    // 평문으로 사용할 상수값들을 인코딩
    Plaintext plain_coeff4, plain_coeff3, plain_coeff2, plain_coeff1, plain_coeff0;
    encoder.encode(1.0, scale, plain_coeff4); // Coefficient of x^4 [level 4]
    encoder.encode(2.0, scale, plain_coeff3); // Coefficient of x^3 [level 4]
    encoder.encode(3.0, scale, plain_coeff2); // Coefficient of x^2 [level 4]
    encoder.encode(4.0, scale, plain_coeff1); // Coefficient of x [level 4]
    encoder.encode(2.0, scale, plain_coeff0); // Constant term [level 4]

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);

    Ciphertext x1_encrypted; // x [level 4]
    encryptor.encrypt(x_plain, x1_encrypted); // x 암호문을 x1_encrypted 에 저장

    Ciphertext x2_encrypted; // x^2 저장
    print_line(__LINE__);
    cout << "Compute (x^2) and relinearize:" << endl;
    evaluator.square(x1_encrypted, x2_encrypted); // x2_encrypted = x^2 [level 4]
    evaluator.relinearize_inplace(x2_encrypted, relin_keys); // x * x 했기 때문에 relinearize, 2^100
    cout << "    + Scale of (x^2) before rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;

    print_line(__LINE__);
    cout << "Rescale (x^2)." << endl;
    evaluator.rescale_to_next_inplace(x2_encrypted); // x2_encrypted = x^2 [level 3] 레벨 감소, 2^100 -> 2^50이 되는건 아닌가?
    cout << "    + Scale of (x^2) after rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;

    x2_encrypted.scale() = pow(2.0, 50); // 2^50으로 스케읿 변경

    print_line(__LINE__);
    cout << "[level 4 : 2 -> level 3 : 2]" << endl;
    parms_id_type last_parms_id = x2_encrypted.parms_id(); // x2_encrypted[level 3] level 3을 last_parms_id에 할당합니다.
    evaluator.mod_switch_to_inplace(plain_coeff3, last_parms_id); // plain_coeff3 = 2 [level 4] -> [level 3]
    // Ciphertext x2_plus_two; // x^2 + 2
    evaluator.add_plain_inplace(x2_encrypted, plain_coeff3); // x2_encrypted에 plain_coeff3 더하여 최종 결과를 계산합니다. // x^2 + 2 [level 3]
    // x2_encrypted = x^2 + 2

    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl; // 세 개의 항이 사용하는 암호화 매개변수가 서로 다르기 때문에 심각한 문제가 발생했음을 나타냅니다.
    cout << "    + Modulus chain index for x2_encrypted(x^2 + 2): "
         << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl; // level : 3
    cout << "    + Modulus chain index for x1_encrypted(x): "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl; // level : 4
    cout << "    + Modulus chain index for plain_coeff3(2): "
         << context.get_context_data(plain_coeff3.parms_id())->chain_index() << endl; // level : 3
    cout << endl;

    print_line(__LINE__);
    cout << "Compute (x + 1)^2 and relinearize." << endl;
    Ciphertext x_plus_one_sq; // (x + 1)^2 [level 4]
    evaluator.add_plain_inplace(x1_encrypted, plain_coeff4); // plain_coeff4 x1_encrypted 더하여 최종 결과를 계산합니다. // x + 1 [level 4]
    evaluator.square(x1_encrypted, x_plus_one_sq); // x1_encrypted(x + 1)의 제곱을 x_plus_one_sq에 저장 [level 4] 2^100
    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys); // 재선형화
    cout << "    + Scale of (x + 1)^2 before rescale: " << log2(x_plus_one_sq.scale()) << " bits" << endl;
    print_line(__LINE__);
    cout << "Rescale (x + 1)^2." << endl;
    evaluator.rescale_to_next_inplace(x_plus_one_sq); // (x + 1)^2 [level 4] - > [level 3]
    cout << "    + Scale of (x + 1)^2 after rescale: " << log2(x_plus_one_sq.scale()) << " bits" << endl;

    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl; // 세 개의 항이 사용하는 암호화 매개변수가 서로 다르기 때문에 심각한 문제가 발생했음을 나타냅니다.
    cout << "    + Modulus chain index for x_plus_one_sq((x + 1)^2): "
         << context.get_context_data(x_plus_one_sq.parms_id())->chain_index() << endl; // level 3

    print_line(__LINE__);
    cout << "The exact scales of all two terms are different:" << endl;
    ios old_fmt(nullptr); // 이전 출력 형식을 저장하기 위해 old_fmt라는 변수를 생성합니다.
    old_fmt.copyfmt(cout); // cout의 현재 출력 형식을 old_fmt로 복사합니다.
    cout << fixed << setprecision(10); // 출력 형식을 고정 소수점 형식으로 설정하고 소수의 정밀도를 10으로 지정합니다.
    cout << "    + Exact scale in (x^2 + 2): " << x2_encrypted.scale() << endl; // x2_encrypted 정확한 스케일을 출력합니다.
    cout << "    + Exact scale in  (x + 1)^2: " << x_plus_one_sq.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt); // 이전 출력 형식을 cout로 복원합니다.

    print_line(__LINE__);
    cout << "Normalize scales to 2^50." << endl; // 스케일을 2^50으로 정규화하기 위해 메시지 출력합니다.
    x2_encrypted.scale() = pow(2.0, 50); // x3_encrypted의 스케일을 2^50으로 변경합니다.
    x_plus_one_sq.scale() = pow(2.0, 50); // x1_encrypted의 스케일을 2^50으로 변경합니다.

    print_line(__LINE__);
    cout << "Compute (x + 1)^2 * (x^2 + 2)" << endl; 
    Ciphertext encrypted_result; // 결과를 저장할 Ciphertext 객체 encrypted_result를 선언합니다.
    evaluator.multiply_inplace(x2_encrypted, x_plus_one_sq); // (x + 1)^2 * (x^2 + 2)
    encrypted_result = x2_encrypted;
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result); // (x + 1)^2 * (x^2 + 2) [level 2]

    /*
    먼저 정확한 결과를 출력합니다.
    */
    Plaintext plain_result; // 결과를 복호화한 후 저장할 Plaintext 객체 plain_result를 선언합니다.
    print_line(__LINE__);
    cout << "Decrypt and decode (x + 1)^2 * (x^2 + 2)" << endl; // PIx^3 + 0.4x + 1을 복호화하고 디코딩하기 위해 메시지를 출력합니다.
    cout << "    + Expected result:" << endl;
    vector<double> true_result; // 예상 결과를 저장할 벡터 true_result를 선언합니다.
    for (size_t i = 0; i < input.size(); i++) // 입력 벡터의 각 요소에 대해 반복합니다.
    {
        double x = input[i]; // 현재 반복에서의 입력 벡터 요소를 x에 할당합니다.
        // 예상 결과를 계산하여 true_result에 추가합니다. 이는 입력 벡터의 각 요소에 대해 PIx^3 + 0.4x + 1을 계산하는 것입니다.
        true_result.push_back(((x + 1) * (x + 1)) * (x * x + 2));
    }
    print_vector(true_result, 3, 7);

    /*
    복호화하고, 디코딩하여 결과를 출력합니다.
    */
    // 암호문 encrypted_result를 복호화하여 결과를 plain_result에 저장합니다. 이를 위해 Decryptor 객체 decryptor가 사용됩니다.
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result; // 결과를 저장할 벡터 result를 선언합니다.
    // plain_result를 디코딩하여 결과를 result 벡터에 저장합니다. 이는 암호문을 실제 값으로 디코딩하는 과정입니다.
    // CKKSEncoder 객체 encoder를 사용하여 디코딩이 수행됩니다.
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);

    cout << "Example: My Rotation" << endl;
    Ciphertext rotated;
    Plaintext plain;
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys); // Galois 키를 생성합니다.
    print_line(__LINE__);
    cout << "Rotate 2 steps left." << endl;
    evaluator.rotate_vector(encrypted_result, 2, galois_keys, rotated); // 암호문 encrypted를 2 단계 왼쪽으로 회전시킵니다.
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(rotated, plain); // 회전된 암호문 rotated를 복호화하여 plain에 저장합니다.
    encoder.decode(plain, result); // plain을 디코딩하여 result에 저장합니다.
    print_vector(result, 3, 7); // result 벡터를 출력합니다.

    /*
    CKKS 스키마에서는 Evaluator::complex_conjugate를 사용하여 암호화된 복소수 벡터에 대한 복소 켤레를 계산할 수도 있습니다.
    이는 사실 회전의 한 종류이며, Galois 키도 필요합니다.
    */
}
