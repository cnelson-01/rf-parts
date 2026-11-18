// SPDX-License-Identifier: MIT
#include "classic.h"
#include <cassert>
#include <random>
#include <iostream>
using namespace w1ble;
static std::vector<uint8_t> packet(uint64_t sync, uint32_t header=0x15555) {
    std::vector<uint8_t> bits;
    for (int i=0;i<4;i++) bits.push_back((sync&1)^(i&1));
    for (int i=0;i<64;i++) bits.push_back((sync>>i)&1);
    for (int i=0;i<4;i++) bits.push_back(((sync>>57)&1)^(i&1));
    for (int i=0;i<18;i++) for(int j=0;j<3;j++) bits.push_back((header>>i)&1);
    return bits;
}
int main() {
    // GIAC published sync sequence 0x475c58cc73345e72 in transmission order;
    // the integer below stores the FIRST transmitted bit in bit zero.
    constexpr uint64_t giac=0x4e7a2cce331a3ae2ULL;
    assert(classic_syncword(0x9e8b33)==giac);
    assert(classic_syncword(0x123456)==0xb048d15a658627c0ULL);
    ClassicObserver observer;
    Burst b; b.rf_channel=78; b.run_id=1; b.sample_index=160000; b.t_wall=1000; b.t_stream=.001;
    b.bit_phases={packet(giac),packet(giac)};
    std::string out;
    observer.observe(b,160e6,out);
    assert(observer.packets()==1);
    assert(out.find("\"lap\":\"9e8b33\"")!=std::string::npos);
    assert(out.find("\"header_fec_errors\":0")!=std::string::npos);
    assert(out.find("\"whitened_header\":\"15555\"")!=std::string::npos);
    assert(out.find("\"profile\":\"unknown\"")!=std::string::npos);
    observer.observe(b,160e6,out); assert(observer.packets()==1); // segment overlap
    b.run_id=2; observer.observe(b,160e6,out); assert(observer.packets()==2);
    b.sample_index+=100000; b.bit_phases[0][15]^=1; b.bit_phases.resize(1);
    observer.observe(b,160e6,out); assert(observer.packets()==2); // corrupt BCH rejected
    b.bit_phases[0].resize(200000); std::mt19937 rng(44);
    for(auto &v:b.bit_phases[0]) v=rng()&1;
    observer.observe(b,160e6,out); assert(observer.packets()==2); // random noise
    auto good=packet(giac);
    b.bit_phases[0].insert(b.bit_phases[0].end(),good.begin(),good.end());
    observer.observe(b,160e6,out); assert(observer.packets()==3); // search far beyond start
    b.run_id=3; b.bit_phases={packet(giac)}; b.bit_phases[0].resize(68);
    out.clear(); observer.observe(b,160e6,out); assert(observer.packets()==4);
    assert(out.find("\"header_fec_errors\":-1")!=std::string::npos); // ID, no header
    std::cout<<"Classic access code, corrupt/noise rejection, dedupe, run reset, long burst: passed\n";
}
