#!/usr/bin/sh
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL=C

echo "# Print info about the Castella round constants and duplex params"
echo
./castella-print-info || exit
echo "________________________________________________________________________________"
echo

echo "# Find the minimum aes_num_rounds for aes_enc_0 to achieve full bit diffusion"
echo
./aes_enc_0-aes_num_rounds -n 300000 || exit
echo "________________________________________________________________________________"
echo

echo "# Find the minimum aes_num_rounds for aes_enc to achieve full bit diffusion"
echo
./aes_enc-aes_num_rounds -n 300000 || exit
echo "________________________________________________________________________________"
echo

echo "# Verify that Castella::permute_inv is the inverse of Castella::permute"
echo
./permute_inv-verify -n 50000 || exit
echo "________________________________________________________________________________"
echo

echo "# Find the minimum num_rounds for Castella::permute to achieve full bit diffusion"
echo
./permute-num_rounds -n 120 || exit
echo "________________________________________________________________________________"
echo

echo "# Print statistics of the avalanche matrix of Castella::permute"
echo
./permute-num_rounds-avalanche_matrix -n 100 || exit
echo "________________________________________________________________________________"
echo

echo "# Structural probes of Castella::permute (subspace escape, fixed points, round constants)"
echo
./permute-structural-probes -n 10000 || exit
echo "________________________________________________________________________________"
echo

echo "# Zero-sum (cube) probes of Castella::permute"
echo
./permute-zero_sum-probes -n 1 || exit
echo "________________________________________________________________________________"
echo

echo "# Find the bit diffusion rate of simd_compress_aes_enc_r{2,3,4} when each param varies"
echo
./simd_compress_aes_enc-num_rounds -n 250000 || exit
echo "________________________________________________________________________________"
echo

echo "# Verify that the lane-paired Castella::permute_x2 matches two separate Castella::permute calls"
echo
./permute_x2-verify -n 70000 || exit
echo "________________________________________________________________________________"
echo

echo "# Verify that the lockstep Castella::DuplexX2 squeezes the same bytes as two separate Castella::Duplex objects"
echo
./duplex_x2-verify -n 3000 || exit
echo "________________________________________________________________________________"
echo

echo "# Verify that the interleaved compress_castella_hash_x2 produces the same digests as two separate compress_castella_hash objects"
echo
./cch_x2-verify -n 3000 || exit
echo "________________________________________________________________________________"
echo
