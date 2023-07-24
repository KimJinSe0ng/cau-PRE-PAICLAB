
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
    print_example_banner("Example: CKKS Basics");

    EncryptionParameters parms(scheme_type::ckks); // 암호화 매개변수 객체를 생성하고, CKKS 스키마를 선택합니다.

    size_t poly_modulus_degree = 8192; // 다항식의 차수를 설정합니다. 이 값은 8192로 설정되어 있습니다.
    parms.set_poly_modulus_degree(poly_modulus_degree); // 암호화 매개변수에 다항식의 차수를 설정합니다.
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 })); // 암호화 매개변수에 계수 모듈러스를 설정합니다.
    // CoeffModulus::Create 함수를 사용하여 각 수준의 소수의 비트 크기를 지정합니다. 위의 예제에서는 60, 40, 40, 60 비트 크기의 소수를 사용합니다.

    double scale = pow(2.0, 40); // 초기 스케일을 설정합니다. 이 예제에서는 2^40으로 설정됩니다.

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
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input; // 입력 벡터를 저장할 벡터를 생성합니다.
    input.reserve(slot_count); // 벡터 input에 slot_count만큼의 메모리 공간을 미리 예약하는 작업입니다.
    /*
    벡터는 동적 배열로, 필요에 따라 크기를 자동으로 조정할 수 있는 자료구조입니다. 예약된 메모리 공간은 벡터의 용량(capacity)을 나타내며, 실제로 저장된 요소의 개수인 크기(size)와는 다릅니다.

    reserve() 함수를 사용하여 메모리 공간을 예약하면, 벡터는 미리 해당 크기의 메모리를 할당받습니다. 이는 벡터에 요소를 추가할 때 메모리를 다시 할당하는 작업을 줄일 수 있어 성능 향상에 도움을 줍니다.

    예를 들어, input.reserve(100)을 호출하면 input 벡터는 적어도 100개의 요소를 저장할 수 있는 메모리 공간을 미리 할당받습니다. 이후 input 벡터에 요소를 추가하면 추가된 요소들이 예약된 메모리 공간에 저장됩니다.

    하지만 reserve() 함수를 호출한다고 해서 실제로 요소가 추가되는 것은 아닙니다. input.size()는 여전히 0이며, 벡터에 저장된 요소가 없습니다. 단지 메모리 공간을 미리 확보하기 위해 예약한 것입니다.

    따라서 input.reserve(slot_count)는 input 벡터에 slot_count만큼의 메모리 공간을 미리 예약하는 역할을 합니다. 이후에 요소를 추가할 때 메모리 재할당이 최소화되어 성능 향상을 기대할 수 있습니다.
    */
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++) // 입력 벡터를 생성하여 input 벡터에 저장합니다. 이 예제에서는 [0, 1] 범위에서 slot_count 개수의 등간격 점을 생성합니다.
    {
        input.push_back(curr_point); // push_back() 메서드는 벡터의 끝에 요소를 추가하는 역할을 합니다.
        curr_point += step_size;
        /**
        위의 코드에서 input.push_back(curr_point)는 curr_point 변수의 값을 input 벡터의 끝에 추가하는 작업을 수행합니다.

        반복문을 통해 curr_point 값을 step_size만큼 증가시키면서, 각 curr_point 값을 input 벡터에 순서대로 추가하게 됩니다. 이렇게 하면 input 벡터는 등간격으로 증가하는 값을 저장하게 됩니다.

        예를 들어, slot_count가 5일 경우, 반복문은 0부터 4까지 실행되며 curr_point는 0, 0.25, 0.5, 0.75, 1의 값을 가지게 됩니다. 각각의 값들이 input 벡터에 순서대로 추가됩니다.

        push_back()은 벡터의 크기를 동적으로 조정하므로, 추가할 요소의 개수에 제한이 없습니다. 벡터는 자동으로 크기를 조정하여 요소를 수용할 수 있습니다.
        */
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7); // 생성된 입력 벡터를 출력합니다.

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    PI, 0.4 및 1에 대한 평문을 생성하기 위해 CKKSEncoder::encode의 오버로드를 사용하여 주어진 부동 소수점 값을 벡터의 모든 슬롯에 인코딩합니다.
    */

    // 평문으로 사용할 상수값들을 인코딩
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    // encoder.encode() 함수를 사용하여 부동 소수점 값을 지정된 스케일과 함께 인코딩하여 plain_coeff3, plain_coeff1, plain_coeff0 평문 객체에 저장합니다.
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    // 입력 벡터 인코딩
    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    // encoder.encode() 함수를 사용하여 주어진 입력 벡터를 지정된 스케일로 인코딩합니다.
    encoder.encode(input, scale, x_plain); // 인코딩된 결과는 x_plain 평문 객체에 저장됩니다.
    // 입력 벡터 암호화
    Ciphertext x1_encrypted;
    // encryptor.encrypt() 함수를 사용하여 x_plain 평문을 암호문으로 변환하여 x1_encrypted 객체에 저장합니다.
    encryptor.encrypt(x_plain, x1_encrypted);

    /*
    x^3을 계산하기 위해 먼저 x^2를 계산하고 재선형화합니다. 그러나 스케일이 이제 2^80으로 증가했습니다.
    */

    // x^2 계산과 재선형화
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    // evaluator.square() 함수를 사용하여 x1_encrypted의 제곱인 x^2을 계산하고, x3_encrypted에 저장합니다.
    evaluator.square(x1_encrypted, x3_encrypted);
    // 이후, evaluator.relinearize_inplace() 함수를 사용하여 x3_encrypted를 재선형화합니다.
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    // 스케일 확인: x3_encrypted.scale()을 통해 x3_encrypted 암호문의 스케일 값을 확인합니다. 이 값은 암호문에 저장된 부동 소수점 값의 정밀도를 나타냅니다.
    cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    이제 rescale을 수행합니다. 모듈러스 스위치에 추가로 스케일이 전환된 소수(40비트 소수)의 인수로 감소됩니다.
    따라서 새로운 스케일은 2^40에 가까워져야 합니다. 그러나 스케일은 2^40과 정확히 동일하지 않습니다.
    이는 40비트 소수가 2^40에 가까울 뿐이기 때문입니다.
    */
    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    // 암호문 x3_encrypted를 다음 레벨로 스케일 다운(rescale)합니다.
    // 이는 모듈러스 스위칭 체인에 추가로 포함된 40비트 소수의 인수로 스케일을 줄입니다. 스케일이 2^40에 가까워야 하지만, 정확히 2^40은 아닙니다.
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    이제 x3_encrypted는 x1_encrypted와 다른 레벨에 있으므로 x^3을 계산하기 위해 곱셈을 수행할 수 없습니다.
    단순히 x1_encrypted를 모듈러스 스위칭 체인에서 다음 매개변수로 전환할 수 있습니다.
    그러나 여전히 x^3 항을 PI (plain_coeff3)와 곱해야 하므로 대신 PIx를 먼저 계산하고 x^2와 곱하여 PIx^3을 얻습니다.
    이를 위해 PI*x를 계산하고 스케일을 2^80에서 2^40에 가까운 값으로 다시 조정합니다.
    */
    print_line(__LINE__);
    cout << "Compute and rescale PI*x." << endl;
    Ciphertext x1_encrypted_coeff3;
    // x1_encrypted와 plain_coeff3를 곱하여 x1_encrypted_coeff3를 계산합니다.
    // 이는 PI (plain_coeff3)와 x1_encrypted를 곱한 PIx를 계산하는 과정입니다.
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    cout << "    + Scale of PI*x before rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;
    // x1_encrypted_coeff3를 다음 레벨로 스케일 다운(rescale)합니다. 이는 2^80 스케일에서 2^40에 가까운 값으로 다시 조정합니다.
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "    + Scale of PI*x after rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;

    /*
    x3_encrypted와 x1_encrypted_coeff3는 정확히 동일한 스케일을 가지고 동일한 암호화 매개변수를 사용하므로 이들을 곱할 수 있습니다.
    결과를 x3_encrypted에 기록하고 재선형화하며, 그리고 rescale을 수행합니다.
    다시 한번 언급하자면 스케일은 2^40에 가까운 값이지만, 다른 소수에 의한 추가적인 스케일링으로 인해 정확히 2^40은 아닙니다.
    우리는 모듈러스 스위칭 체인에서 마지막 레벨에 도달했습니다.
    */
    print_line(__LINE__);
    cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
    // x3_encrypted와 x1_encrypted_coeff3를 곱하여 결과를 x3_encrypted에 기록합니다. 이는 PIx^3을 계산하는 과정입니다.
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    // x3_encrypted를 재선형화합니다. 이는 다항식 계산을 위해 필요한 단계입니다.
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of PI*x^3 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;
    // x3_encrypted를 다음 레벨로 스케일 다운(rescale)합니다. 이는 마지막 레벨인 모듈러스 스위칭 체인의 레벨에 도달한 것을 나타냅니다.
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of PI*x^3 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    /*
    다음으로 일차항을 계산합니다. 이를 위해 plain_coeff1과의 multiply_plain 연산이 필요합니다. 결과로 x1_encrypted를 덮어씁니다.
    */
    print_line(__LINE__);
    cout << "Compute and rescale 0.4*x." << endl;
    // x1_encrypted와 plain_coeff1을 곱하여 결과를 x1_encrypted에 덮어씁니다. 이는 0.4x를 계산하는 과정입니다.
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "    + Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
    // x1_encrypted를 다음 레벨로 스케일 다운(rescale)합니다. 이는 2^80 스케일에서 2^40에 가까운 값으로 다시 조정합니다.
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    /*
    이제 세 항의 합을 계산하길 원합니다. 그러나 심각한 문제가 있습니다: rescaling으로 인해 세 항이 사용하는 암호화 매개변수가 서로 다릅니다.

    암호화된 덧셈과 뺄셈은 입력의 스케일이 동일하고, 또한 암호화 매개변수 (parms_id)가 일치해야 합니다.
    일치하지 않는 경우, Evaluator에서 예외가 발생합니다.
    */
    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl; // 세 개의 항이 사용하는 암호화 매개변수가 서로 다르기 때문에 심각한 문제가 발생했음을 나타냅니다.
    cout << "    + Modulus chain index for x3_encrypted: "
         << context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl; // level : 0
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl; // level : 1
    cout << "    + Modulus chain index for plain_coeff0: "
         << context.get_context_data(plain_coeff0.parms_id())->chain_index() << endl; // level : 2
    cout << endl;

    /*
    이 시점에서 스케일에 대해 주의깊게 고려해 봅시다. coeff_modulus에서 소수를 P_0, P_1, P_2, P_3으로 표시합니다.
    P_3은 특수 모듈러스로 사용되며 rescaling에 참여하지 않습니다. 위의 계산 후 암호문의 스케일은 다음과 같습니다:

        - Product x^2의 스케일은 2^80이고 레벨 2에 있습니다.
        - Product PI*x의 스케일은 2^80이고 레벨 2에 있습니다.
        - 두 항을 스케일 2^80/P_2로 rescaling하여 레벨 1로 축소했습니다.
        - Product PI*x^3의 스케일은 (2^80/P_2)^2입니다.
        - 이를 스케일 (2^80/P_2)^2/P_1로 rescaling하여 레벨 0으로 축소했습니다.
        - Product 0.4*x의 스케일은 2^80입니다.
        - 이를 스케일 2^80/P_2로 rescaling하여 레벨 1로 축소했습니다.
        - 상수 항 1의 스케일은 2^40이고 레벨 2에 있습니다.

    세 항의 스케일은 모두 대략 2^40이지만, 정확한 값은 서로 다르기 때문에 이들을 더할 수 없습니다.
    */
    print_line(__LINE__);
    cout << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr); // 이전 출력 형식을 저장하기 위해 old_fmt라는 변수를 생성합니다.
    old_fmt.copyfmt(cout); // cout의 현재 출력 형식을 old_fmt로 복사합니다.
    cout << fixed << setprecision(10); // 출력 형식을 고정 소수점 형식으로 설정하고 소수의 정밀도를 10으로 지정합니다.
    cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl; // x3_encrypted의 정확한 스케일을 출력합니다.
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt); // 이전 출력 형식을 cout로 복원합니다.

    /*
    이 문제를 해결하는 방법은 여러 가지가 있습니다.
    P_2와 P_1이 실제로 2^40에 매우 가깝기 때문에, 우리는 간단히 Microsoft SEAL에게 "거짓말"을 하여 스케일을 동일하게 설정할 수 있습니다.
    예를 들어, PIx^3의 스케일을 2^40로 변경하는 것은 PIx^3의 값을 2^120/(P_2^2*P_1)으로 스케일링하는 것을 의미합니다.
    이 값은 거의 1에 가깝기 때문에 실용적인 오차는 거의 없을 것입니다.

    또 다른 옵션은 스케일이 2^80/P_2인 1을 인코딩하고, 0.4*x와 multiply_plain 연산을 수행한 다음 스케일을 조정하는 것입니다.
    이 경우에는 1을 적절한 암호화 매개변수 (parms_id)로 인코딩해야 하는 추가적인 작업이 필요합니다.

    이 예제에서는 가장 간단한 접근 방식인 첫 번째 방법을 사용하여 PIx^3과 0.4x의 스케일을 2^40로 변경하기로 합니다.
    */
    print_line(__LINE__);
    cout << "Normalize scales to 2^40." << endl; // 스케일을 2^40으로 정규화하기 위해 메시지 출력합니다.
    x3_encrypted.scale() = pow(2.0, 40); // x3_encrypted의 스케일을 2^40으로 변경합니다.
    x1_encrypted.scale() = pow(2.0, 40); // x1_encrypted의 스케일을 2^40으로 변경합니다.

    /*
    여전히 암호화 매개변수가 일치하지 않는 문제가 있습니다. 이 문제는 전통적인 모듈러스 스위칭 (rescaling 없이)을 사용하여 쉽게 해결할 수 있습니다.
    CKKS는 BFV 스키마와 마찬가지로 모듈러스 스위칭을 지원하여 계수 modulus의 일부를 필요하지 않을 때 제거할 수 있도록 합니다.
    */
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl; // 암호화 매개변수를 가장 낮은 레벨로 정규화하기 위해 메시지 출력합니다.
    parms_id_type last_parms_id = x3_encrypted.parms_id(); // x3_encrypted의 암호화 매개변수 ID를 가져와 last_parms_id에 할당합니다.
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id); // x1_encrypted의 암호화 매개변수를 last_parms_id로 변경합니다.
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    /*
    이제 세 개의 암호문은 호환되며 덧셈이 가능합니다.
    */
    print_line(__LINE__);
    cout << "Compute PI*x^3 + 0.4*x + 1." << endl; // PIx^3 + 0.4x + 1을 계산하기 위해 메시지 출력합니다.
    Ciphertext encrypted_result; // 결과를 저장할 Ciphertext 객체 encrypted_result를 선언합니다.
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result); // x3_encrypted와 x1_encrypted를 더하고 결과를 encrypted_result에 저장합니다.
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0); // encrypted_result에 plain_coeff0를 더하여 최종 결과를 계산합니다.

    /*
    먼저 정확한 결과를 출력합니다.
    */
    Plaintext plain_result; // 결과를 복호화한 후 저장할 Plaintext 객체 plain_result를 선언합니다.
    print_line(__LINE__);
    cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl; // PIx^3 + 0.4x + 1을 복호화하고 디코딩하기 위해 메시지를 출력합니다.
    cout << "    + Expected result:" << endl;
    vector<double> true_result; // 예상 결과를 저장할 벡터 true_result를 선언합니다.
    for (size_t i = 0; i < input.size(); i++) // 입력 벡터의 각 요소에 대해 반복합니다.
    {
        double x = input[i]; // 현재 반복에서의 입력 벡터 요소를 x에 할당합니다.
        // 예상 결과를 계산하여 true_result에 추가합니다. 이는 입력 벡터의 각 요소에 대해 PIx^3 + 0.4x + 1을 계산하는 것입니다.
        true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
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

    /*
    이 예제에서는 복소수에 대한 계산을 보여주지는 않았지만, CKKSEncoder를 사용하면 이를 쉽게 수행할 수 있습니다.
    복소수의 덧셈과 곱셈은 예상한 대로 작동합니다.
    */
}
