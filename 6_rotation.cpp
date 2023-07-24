// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

/*
BFV 및 BGV 스키마 (BatchEncoder를 사용한 경우) 및 CKKS 스키마는 암호화된 숫자에 대한 네이티브 벡터화된 계산을 지원합니다.
슬롯별 계산 외에도, 암호화된 벡터를 순환적으로 회전시킬 수 있습니다.

단순히 scheme_type::bfv를 scheme_type::bgv로 변경하면 이 예제를 BGV 스키마에서 작동시킬 수 있습니다.

*/
void example_rotation_bfv()
{
    print_example_banner("Example: Rotation / Rotation in BFV");

    EncryptionParameters parms(scheme_type::bfv); // BFV 스키마를 사용하여 암호화 매개변수를 설정합니다.

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree); // 다항식 모듈러스의 차수를 설정합니다.
    // 다항식 계수의 모듈러스를 설정합니다. CoeffModulus::BFVDefault 함수는 주어진 다항식 모듈러스 차수에 대한 기본 모듈러스 세트를 생성합니다.
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // 평문 모듈러스를 설정합니다. Batching 함수는 주어진 다항식 모듈러스 차수와 비트 수에 대한 적합한 평문 모듈러스를 생성합니다.
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms); // 암호 컨텍스트를 생성하고 암호화 매개변수를 사용하여 초기화합니다.
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context); //  암호화 키 생성기를 생성하고 암호 컨텍스트를 사용하여 초기화합니다.
    SecretKey secret_key = keygen.secret_key(); // 비밀 키를 생성합니다.
    PublicKey public_key;
    keygen.create_public_key(public_key); // 공개 키를 생성합니다.
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // 재선형화 키를 생성합니다.
    Encryptor encryptor(context, public_key); // 암호화 객체를 생성하고 암호 컨텍스트와 공개 키를 사용하여 초기화합니다.
    Evaluator evaluator(context); // 평가자 객체를 생성하고 암호 컨텍스트를 사용하여 초기화합니다.
    Decryptor decryptor(context, secret_key); // 복호화 객체를 생성하고 암호 컨텍스트와 비밀 키를 사용하여 초기화합니다.

    BatchEncoder batch_encoder(context); // 배치 인코더 객체를 생성하고 암호 컨텍스트를 사용하여 초기화합니다.
    size_t slot_count = batch_encoder.slot_count(); // 슬롯의 개수를 가져옵니다.
    size_t row_size = slot_count / 2; // 행의 크기를 슬롯 개수의 절반으로 설정합니다.
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL); // 슬롯 개수만큼의 크기로 초기화된 0으로 채워진 벡터 pod_matrix를 생성합니다.
    pod_matrix[0] = 0ULL; // pod_matrix에 행렬 요소 값을 설정합니다
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    먼저 BatchEncoder를 사용하여 행렬을 평문으로 인코딩합니다. 그런 다음 일반적인 방법으로 평문을 암호화합니다.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    batch_encoder.encode(pod_matrix, plain_matrix); // pod_matrix를 평문으로 인코딩하여 plain_matrix에 저장합니다.
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix); // 평문 plain_matrix를 암호화하여 encrypted_matrix에 저장합니다.
    // 암호문 encrypted_matrix의 불변 잡음 예산을 확인합니다. (잡음 예산은 회전 연산에 영향을 주지 않음)
    cout << "    + Noise budget in fresh encryption: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << endl;

    /*
    회전은 Galois keys라고 불리는 또 다른 특수 키 유형을 필요로 합니다. 이는 KeyGenerator에서 쉽게 얻을 수 있습니다.
    */
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    /*
    이제 행렬의 각 행을 왼쪽으로 3단계 회전시키고, 복호화하고, 디코딩하여 출력합니다.
    */
    print_line(__LINE__);
    cout << "Rotate rows 3 steps left." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, 3, galois_keys); // 암호문 encrypted_matrix의 각 행을 왼쪽으로 3단계 회전시킵니다.
    Plaintext plain_result;
    // 암호문 encrypted_matrix의 불변 잡음 예산을 확인합니다.
    cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result); // 암호문 encrypted_matrix를 복호화하여 plain_result에 저장합니다.
    batch_encoder.decode(plain_result, pod_matrix); // plain_result를 디코딩하여 pod_matrix에 저장합니다.
    print_matrix(pod_matrix, row_size);

    /*
    열도 회전시킬 수 있습니다. 즉, 행을 교환합니다.
    */
    print_line(__LINE__);
    cout << "Rotate columns." << endl;
    evaluator.rotate_columns_inplace(encrypted_matrix, galois_keys); // 암호문 encrypted_matrix의 각 열을 회전시킵니다.
    cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result); // 암호문 encrypted_matrix를 복호화하여 plain_result에 저장합니다.
    batch_encoder.decode(plain_result, pod_matrix); // plain_result를 디코딩하여 pod_matrix에 저장합니다.
    print_matrix(pod_matrix, row_size);

    /*
    마지막으로 행을 오른쪽으로 4단계 회전시키고, 복호화하고, 디코딩하여 출력합니다.
    */
    print_line(__LINE__);
    cout << "Rotate rows 4 steps right." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, galois_keys); // 암호문 encrypted_matrix의 각 행을 오른쪽으로 4단계 회전시킵니다.
    cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result); // 암호문 encrypted_matrix를 복호화하여 plain_result에 저장합니다.
    batch_encoder.decode(plain_result, pod_matrix); // plain_result를 디코딩하여 pod_matrix에 저장합니다.
    print_matrix(pod_matrix, row_size);

    /*
    회전은 잡음 예산을 소비하지 않는다는 점에 유의하세요. 그러나 이는 특수 소수가 다른 소수와 적어도 같은 크기를 가져야 하는 경우에만 해당됩니다.
    재선형화에도 동일한 원칙이 적용됩니다. Microsoft SEAL은 특수 소수의 특정 크기를 요구하지 않으므로 이를 보장하는 것은 사용자의 책임입니다.
    */
}

void example_rotation_ckks()
{
    print_example_banner("Example: Rotation / Rotation in CKKS");

    /*
    CKKS 스키마에서의 회전은 BFV에서의 회전과 매우 유사하게 작동합니다.
    */
    EncryptionParameters parms(scheme_type::ckks); // CKKS 스키마를 사용하여 암호화 매개변수를 설정합니다.

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree); // 다항식 모듈러스의 차수를 설정합니다.
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 })); // 계수 모듈러스를 설정합니다. 

    SEALContext context(parms); // 암호 컨텍스트를 생성하고 암호화 매개변수를 사용하여 초기화합니다.
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context); // 암호화 키 생성기를 생성하고 암호 컨텍스트를 사용하여 초기화합니다.
    SecretKey secret_key = keygen.secret_key(); // 비밀 키를 생성합니다.
    PublicKey public_key;
    keygen.create_public_key(public_key); // 공개 키를 생성합니다.
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys); // 재선형화 키를 생성합니다.
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys); // Galois 키를 생성합니다.
    Encryptor encryptor(context, public_key); // 암호화 객체를 생성하고 암호 컨텍스트와 공개 키를 사용하여 초기화합니다.
    Evaluator evaluator(context); // 평가자 객체를 생성하고 암호 컨텍스트를 사용하여 초기화합니다.
    Decryptor decryptor(context, secret_key); // 복호화 객체를 생성하고 암호 컨텍스트와 비밀 키를 사용하여 초기화합니다.

    CKKSEncoder ckks_encoder(context); // CKKS 인코더 객체를 생성하고 암호 컨텍스트를 사용하여 초기화합니다.

    size_t slot_count = ckks_encoder.slot_count(); // 슬롯의 개수를 가져옵니다.
    cout << "Number of slots: " << slot_count << endl;
    vector<double> input; // 입력 벡터를 저장할 벡터 input을 생성합니다.
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector:" << endl;
    print_vector(input, 3, 7);

    auto scale = pow(2.0, 50); // 스케일 파라미터를 설정합니다.

    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    Plaintext plain;
    ckks_encoder.encode(input, scale, plain); // 입력 벡터를 평문으로 인코딩하여 plain에 저장합니다.
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted); // 평문 plain을 암호화하여 encrypted에 저장합니다.

    Ciphertext rotated;
    print_line(__LINE__);
    cout << "Rotate 2 steps left." << endl;
    evaluator.rotate_vector(encrypted, 2, galois_keys, rotated); // 암호문 encrypted를 2 단계 왼쪽으로 회전시킵니다.
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(rotated, plain); // 회전된 암호문 rotated를 복호화하여 plain에 저장합니다.
    vector<double> result;
    ckks_encoder.decode(plain, result); // plain을 디코딩하여 result에 저장합니다.
    print_vector(result, 3, 7); // result 벡터를 출력합니다.

    /*
    CKKS 스키마에서는 Evaluator::complex_conjugate를 사용하여 암호화된 복소수 벡터에 대한 복소 켤레를 계산할 수도 있습니다.
    이는 사실 회전의 한 종류이며, Galois 키도 필요합니다.
    */
}

void example_rotation()
{
    print_example_banner("Example: Rotation");

    /*
    모든 회전 예제를 실행합니다.
    */
    example_rotation_bfv();
    example_rotation_ckks();
}
