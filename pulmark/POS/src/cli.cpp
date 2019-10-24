// Copyright 2018 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <ctime>
#include <set>

#include "include/cxxopts.hpp"
#include "include/picosha2.hpp"

#include "include/plotter_disk.hpp"
#include "include/prover_disk.hpp"
#include "include/verifier.hpp"

void HexToBytes(const std::string &hex, uint8_t *result) {
  for (uint32_t i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    result[i / 2] = byte;
  }
}

std::vector<unsigned char> intToBytes(uint32_t paramInt, uint32_t numBytes) {
  std::vector<unsigned char> arrayOfByte(numBytes, 0);
  for (uint32_t i = 0; paramInt > 0; i++) {
    arrayOfByte[numBytes - i - 1] = paramInt & 0xff;
    paramInt >>= 8;
  }
  return arrayOfByte;
}

std::string Strip0x(const std::string &hex) {
  if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") {
    return hex.substr(2);
  }
  return hex;
}

void HelpAndQuit(cxxopts::Options options) {
  std::cout << options.help({""}) << std::endl;
  std::cout << "./ProofOfSpace generate" << std::endl;
  std::cout << "./ProofOfSpace prove <challenge>" << std::endl;
  std::cout << "./ProofOfSpace verify <challenge> <proof>" << std::endl;
  std::cout << "./ProofOfSpace check" << std::endl;
  exit(0);
}

int main(int argc, char *argv[]) {

  std::ios_base::sync_with_stdio(false);
  std::cin.tie(nullptr);

  try {
    cxxopts::Options options(
        "ProofOfSpace",
        "Utility for plotting, generating and verifying proofs of space.");
    options.positional_help("(generate/prove/verify/check) param1 param2 ")
        .show_positional_help();

    // Default values
    uint8_t k = 20;
    std::string filename = "plot.dat";
    std::string operation = "help";
    std::string memo = "0102030405";
    std::string id =
        "022fb42c08c12de3a6af053880199806532e79515f94e83461612101f9412f9e";

    options.allow_unrecognised_options().add_options()(
        "k, size", "Plot size", cxxopts::value<uint8_t>(k))(
        "f, file", "Filename", cxxopts::value<std::string>(filename))(
        "m, memo", "Memo to insert into the plot",
        cxxopts::value<std::string>(memo))(
        "i, id", "Unique 32-byte seed for the plot",
        cxxopts::value<std::string>(id))("help", "Print help");

    auto result = options.parse(argc, argv);

    if (result.count("help") || argc < 2) {
      HelpAndQuit(options);
    }
    operation = argv[1];

    if (operation == "help") {
      HelpAndQuit(options);
    } else if (operation == "generate") {
      std::cout << "Generating plot for k=" << static_cast<int>(k)
                << " filename=" << filename << " id=" << id << std::endl
                << std::endl;
      if (id.size() != 64) {
        std::cout << "Invalid ID, should be 32 bytes" << std::endl;
        exit(1);
      }
      memo = Strip0x(memo);
      id = Strip0x(id);
      uint8_t memo_bytes[memo.size() / 2];
      uint8_t id_bytes[32];

      HexToBytes(memo, memo_bytes);
      HexToBytes(id, id_bytes);

      DiskPlotter plotter = DiskPlotter();
      plotter.CreatePlotDisk(filename, k, memo_bytes, 5, id_bytes, 32);
    } else if (operation == "prove") {
      if (argc < 3) {
        HelpAndQuit(options);
      }
      std::cout << "Proving using filename=" << filename
                << " challenge=" << argv[2] << std::endl
                << std::endl;
      std::string challenge = Strip0x(argv[2]);
      if (challenge.size() != 64) {
        std::cout << "Invalid challenge, should be 32 bytes" << std::endl;
        exit(1);
      }
      uint8_t challenge_bytes[32];
      HexToBytes(challenge, challenge_bytes);

      DiskProver prover(filename);
      std::vector<LargeBits> qualities =
          prover.GetQualitiesForChallenge(challenge_bytes);
      for (uint32_t i = 0; i < qualities.size(); i++) {
        k = qualities[i].GetSize() / 2;
        uint8_t proof_data[8 * k];
        LargeBits proof = prover.GetFullProof(challenge_bytes, i);
        proof.ToBytes(proof_data);
        std::cout << "Proof: 0x" << Util::HexStr(proof_data, k * 8)
                  << std::endl;
      }
      if (qualities.empty()) {
        std::cout << "No proofs found." << std::endl;
        exit(1);
      }
    } else if (operation == "verify") {
      if (argc < 4) {
        HelpAndQuit(options);
      }
      std::cout << "Verifying proof=" << argv[2] << " for challenge=" << argv[3]
                << " and k=" << static_cast<int>(k) << std::endl
                << std::endl;
      Verifier verifier = Verifier();

      id = Strip0x(id);
      std::string proof = Strip0x(argv[2]);
      std::string challenge = Strip0x(argv[3]);
      if (id.size() != 64) {
        std::cout << "Invalid ID, should be 32 bytes" << std::endl;
        exit(1);
      }
      if (challenge.size() != 64) {
        std::cout << "Invalid challenge, should be 32 bytes" << std::endl;
        exit(1);
      }
      uint8_t id_bytes[32];
      uint8_t challenge_bytes[32];
      uint8_t proof_bytes[proof.size() / 2];
      HexToBytes(id, id_bytes);
      HexToBytes(challenge, challenge_bytes);
      HexToBytes(proof, proof_bytes);

      LargeBits quality = verifier.ValidateProof(id_bytes, k, challenge_bytes,
                                                 proof_bytes, k * 8);
      if (quality.GetSize() == 2 * k) {
        std::cout << "Proof verification succeeded. Quality: " << quality
                  << std::endl;
      } else {
        std::cout << "Proof verification failed." << std::endl;
        exit(1);
      }
    } else if (operation == "check") {
      uint32_t iterations = 1000;
      if (argc == 3) {
        iterations = std::stoi(argv[2]);
      }

      DiskProver prover(filename);
      Verifier verifier = Verifier();

      uint32_t success = 0;
      id = Strip0x(id);
      uint8_t id_bytes[32];
      HexToBytes(id, id_bytes);

      for (uint32_t num = 0; num < iterations; num++) {
        std::vector<unsigned char> hash_input = intToBytes(num, 4);
        hash_input.insert(hash_input.end(), &id_bytes[0], &id_bytes[32]);

        std::vector<unsigned char> hash(picosha2::k_digest_size);
        picosha2::hash256(hash_input.begin(), hash_input.end(), hash.begin(),
                          hash.end());

        std::vector<LargeBits> qualities =
            prover.GetQualitiesForChallenge(hash.data());
        for (uint32_t i = 0; i < qualities.size(); i++) {
          k = qualities[i].GetSize() / 2;
          LargeBits proof = prover.GetFullProof(hash.data(), i);
          uint8_t proof_data[proof.GetSize() / 8];
          proof.ToBytes(proof_data);
          std::cout << "i: " << num << std::endl;
          std::cout << "challenge: 0x" << Util::HexStr(hash.data(), 256 / 8)
                    << std::endl;
          std::cout << "proof: 0x" << Util::HexStr(proof_data, k * 8)
                    << std::endl;
          LargeBits quality = verifier.ValidateProof(id_bytes, k, hash.data(),
                                                     proof_data, k * 8);
          if (quality.GetSize() == 2 * k) {
            std::cout << "quality: " << quality << std::endl;
            std::cout << "Proof verification suceeded. k = "
                      << static_cast<int>(k) << std::endl;
            success++;
          } else {
            std::cout << "Proof verification failed." << std::endl;
            exit(1);
          }
        }
      }
      std::cout << "Total success: " << success << "/" << iterations << ", "
                << (success / static_cast<double>(iterations)) << "%."
                << std::endl;
    } else {
      std::cout << "Invalid operation. Use generate/prove/verify/check"
                << std::endl;
    }
    exit(0);
  } catch (const cxxopts::OptionException &e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    exit(1);
  }
}
