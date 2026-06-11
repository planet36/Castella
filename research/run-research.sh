#!/usr/bin/bash
# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

export LC_ALL=C

echo "# Print info about the Castella round constants and duplex params"
echo
./castella-print-info || exit
echo "________________________________________________________________________________"
echo

echo "# Find the optimal aes_num_rounds for Castella::utils::aes_enc_0"
echo
./aes_enc_0-aes_num_rounds -n 300000 || exit
echo "________________________________________________________________________________"
echo

echo "# For each state size, find the optimal num_rounds for Castella::permute"
echo
./permute-num_rounds -n 120 || exit
echo "________________________________________________________________________________"
echo

echo "# Verify that Castella::permute_inv is the inverse of Castella::permute"
echo
./permute_inv-verify -n 50000 || exit
echo "________________________________________________________________________________"
echo
