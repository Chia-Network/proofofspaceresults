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

#ifndef PLOTTER_DISK_P0_HPP
#define PLOTTER_DISK_P0_HPP

#ifdef USE_HELLMAN_ATTACK
void DiskPlotter::BuildExtraStorage(const std::string &filename, int k,
                                    uint8_t *id,
                                    std::vector<uint64_t> &extra_metadata) {
  Attacker attacker(pow(2, ((double)k * 2 / 3)), pow(2, ((double)k / 3)),
                    (1LL << k), 5, id);
  attacker.BuildTable();
  std::cout << "\t\tHellman table complete" << std::endl;
  attacker.BuildFileExtraStorage(filename, sort_memory_.get(),
                                 Sort::kSortMemorySize, extra_metadata);
  std::cout << "Disk Extra storage complete" << std::endl;
}
#endif

#endif // PLOTTER_DISK_P0_HPP
