//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
// Copyright (c) 2018 Chia Network Inc
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include <iostream>

#include <boost/program_options.hpp>

#include <nil/crypto3/block/algorithm/encrypt.hpp>
#include <nil/crypto3/block/rijndael.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <chia/plotter_disk.hpp>
#include <chia/prover_disk.hpp>
#include <chia/verifier.hpp>
#include <chia/picosha2.hpp>

using namespace nil::crypto3;

void hex_to_bytes(const std::string &hex, uint8_t *result) {
    for (uint32_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        result[i / 2] = byte;
    }
}

std::vector<unsigned char> int_to_bytes(uint32_t paramInt, uint32_t numBytes) {
    std::vector<unsigned char> arrayOfByte(numBytes, 0);
    for (uint32_t i = 0; paramInt > 0; i++) {
        arrayOfByte[numBytes - i - 1] = paramInt & 0xff;
        paramInt >>= 8;
    }
    return arrayOfByte;
}

std::string strip0x(const std::string &hex) {
    if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") {
        return hex.substr(2);
    }
    return hex;
}

int main(int argc, char *argv[]) {
    boost::program_options::options_description options(
        "ProofOfSpace. Utility for plotting, generating and verifying proofs of space.");

    // Default values
    std::uint32_t k;
    std::size_t iterations;
    std::string filename, memo, id, challenge, proof;

    options.add_options()("size,k", boost::program_options::value<std::uint32_t>(&k)->default_value(20), "Plot size")(
        "file,f", boost::program_options::value<std::string>(&filename)->default_value("plot.dat"), "Filename")(
        "memo,m", boost::program_options::value<std::string>(&memo)->default_value("0102030405"),
        "Memo to insert into the plot")("id,i",
                                        boost::program_options::value<std::string>(&id)->default_value(
                                            "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e"),
                                        "Unique 32-byte seed for the plot")("generate", "Operation to perform")(
        "challenge", boost::program_options::value<std::string>(&challenge),
        "Operation to perform")("verify", boost::program_options::value<std::string>(&proof), "Operation to perform")(
        "check", boost::program_options::value<std::size_t>(&iterations)->default_value(1000), "Operation to perform")(
        "prove", boost::program_options::value<std::string>(&challenge), "Operation to perform")("help", "Print help");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 1;
    } else if (vm.count("generate")) {
        std::cout << "Generating plot for k=" << static_cast<int>(k) << " filename=" << filename << " id=" << id
                  << std::endl
                  << std::endl;
        if (id.size() != 64) {
            std::cout << "Invalid ID, should be 32 bytes" << std::endl;
            return 1;
        }
        memo = strip0x(memo);
        id = strip0x(id);
        uint8_t memo_bytes[memo.size() / 2];
        uint8_t id_bytes[32];

        hex_to_bytes(memo, memo_bytes);
        hex_to_bytes(id, id_bytes);

        disk_plotter plotter = disk_plotter();
        plotter.create_plot_disk(filename, k, memo_bytes, 5, id_bytes, 32);
    } else if (vm.count("prove")) {
        if (argc < 3) {
            std::cout << options << std::endl;
        }
        std::cout << "Proving using filename=" << filename << " challenge=" << challenge << std::endl << std::endl;
        challenge = strip0x(challenge);
        if (challenge.size() != 64) {
            std::cout << "Invalid challenge, should be 32 bytes" << std::endl;
            return 1;
        }
        uint8_t challenge_bytes[32];
        hex_to_bytes(challenge, challenge_bytes);

        disk_prover prover(filename);
        std::vector<large_bits> qualities = prover.get_qualities_for_challenge(challenge_bytes);
        for (std::size_t i = 0; i < qualities.size(); i++) {
            k = qualities[i].size() / 2;
            uint8_t proof_data[8 * k];
            prover.get_full_proof(challenge_bytes, i).to_bytes(proof_data);
            std::cout << "Proof: 0x" << utilities::hex_str(proof_data, k * 8) << std::endl;
        }
        if (qualities.empty()) {
            std::cout << "No proofs found." << std::endl;
            return 1;
        }
    } else if (vm.count("verify") && vm.count("challenge")) {
        if (argc < 4) {
            std::cout << options << std::endl;
        }
        std::cout << "Verifying proof=" << proof << " for challenge=" << challenge << " and k=" << static_cast<int>(k)
                  << std::endl
                  << std::endl;
        verifier ver = verifier();

        id = strip0x(id);
        proof = strip0x(proof);
        challenge = strip0x(challenge);
        if (id.size() != 64) {
            std::cout << "Invalid ID, should be 32 bytes" << std::endl;
            return 1;
        }
        if (challenge.size() != 64) {
            std::cout << "Invalid challenge, should be 32 bytes" << std::endl;
            return 1;
        }
        uint8_t id_bytes[32];
        uint8_t challenge_bytes[32];
        uint8_t proof_bytes[proof.size() / 2];
        hex_to_bytes(id, id_bytes);
        hex_to_bytes(challenge, challenge_bytes);
        hex_to_bytes(proof, proof_bytes);

        large_bits quality = ver.validate_proof(id_bytes, k, challenge_bytes, proof_bytes, k * 8);
        if (quality.size() == 2 * k) {
            std::cout << "Proof verification succeeded. Quality: " << quality << std::endl;
        } else {
            std::cout << "Proof verification failed." << std::endl;
            return 1;
        }
    } else if (vm.count("check")) {
        disk_prover prover(filename);
        verifier ver = verifier();

        uint32_t success = 0;
        id = strip0x(id);
        uint8_t id_bytes[32];
        hex_to_bytes(id, id_bytes);

        for (uint32_t num = 0; num < iterations; num++) {
            std::vector<unsigned char> hash_input = int_to_bytes(num, 4);
            hash_input.insert(hash_input.end(), &id_bytes[0], &id_bytes[32]);

            //            std::vector<std::uint8_t> hash =
            //            nil::crypto3::hash::hash<nil::crypto3::hash::sha2<256>>(hash_input);
            std::vector<unsigned char> hash(picosha2::k_digest_size);
            picosha2::hash256(hash_input.begin(), hash_input.end(), hash.begin(), hash.end());

            std::vector<large_bits> qualities = prover.get_qualities_for_challenge(hash.data());
            for (uint32_t i = 0; i < qualities.size(); i++) {
                k = qualities[i].size() / 2;
                large_bits proof = prover.get_full_proof(hash.data(), i);
                uint8_t proof_data[proof.size() / 8];
                proof.to_bytes(proof_data);
                std::cout << "i: " << num << std::endl;
                std::cout << "challenge: 0x" << utilities::hex_str(hash.data(), 256 / 8) << std::endl;
                std::cout << "proof: 0x" << utilities::hex_str(proof_data, k * 8) << std::endl;
                large_bits quality = ver.validate_proof(id_bytes, k, hash.data(), proof_data, k * 8);
                if (quality.size() == 2 * k) {
                    std::cout << "quality: " << quality << std::endl;
                    std::cout << "Proof verification succeeded. k = " << static_cast<int>(k) << std::endl;
                    success++;
                } else {
                    std::cout << "Proof verification failed." << std::endl;
                    return 1;
                }
            }
        }
        std::cout << "Total success: " << success << "/" << iterations << ", "
                  << (success / static_cast<double>(iterations)) << "%." << std::endl;
    } else {
        std::cout << "Invalid operation. Use generate/prove/verify/check" << std::endl;
    }
    return 0;
}
