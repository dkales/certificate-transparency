#pragma once

#include <vector>
#include <cstdint>
#include <x86intrin.h>

#include "alignment_allocator.h"
#include "Defines.h"


class hashdatastore {
public:
    typedef __m256i hash_type;

    hashdatastore() = default;
    hashdatastore(span<hash_type> data) : data_(data) {}

    void reserve(size_t n) { dummy_data_.reserve(n); }
    void push_back(const hash_type& data) { dummy_data_.push_back(data); }
    void push_back(hash_type&& data) { dummy_data_.emplace_back(std::move(data)); }

    void create_dummy(size_t n) { dummy_data_.resize(n, _mm256_set_epi64x(1,2,3,4)); }
    void use_dummy_data() { data_ = span<hash_type>(dummy_data_.data(), dummy_data_.size()); }

    size_t size() const { return data_.size(); }

    hash_type answer_pir1(const std::vector<uint8_t>& indexing) const;
    hash_type answer_pir2(const std::vector<uint8_t>& indexing) const;
    hash_type answer_pir3(const std::vector<uint8_t>& indexing) const;
    hash_type answer_pir4(const std::vector<uint8_t>& indexing) const;
    hash_type answer_pir5(const std::vector<uint8_t>& indexing) const;
    hash_type answer_pir_idea_speed_comparison(const std::vector<uint8_t>& indexing) const;


private:
    std::vector<hash_type, AlignmentAllocator<hash_type, sizeof(hash_type)> > dummy_data_;
    span<hash_type> data_;

};

