source("functions.r")

# DECRYPT
random <- "rsa_random_exp_dec2.txt"
high <- "rsa_high_hw_dec.txt"
low <- "rsa_low_hw_dec.txt"
  
rsa_graphs(random, high,  low, "Comparison of times while using different exponents", "rsa_combined_exp.png")
generateTimeSequence(random,high,low,"seq")
# SIGN

random <- "rsa_random_exp_sig2.txt"
high <- "rsa_high_hw_sign.txt"
low <- "rsa_low_hw_sign.txt"

rsa_graphs(random, high,  low, "Comparison of times while using different exponents", "rsa_combined_exp.png")
generateTimeSequence(random,high,low,"seq")
# ECC

random <- "ecc_random_exp.txt"
high <- "ecc_large_exponent.txt"
low <- "ecc_short_exponent.txt"

ecc_graphs(random, high,  low, "Comparison of times while using different exponents", "rsa_combined_exp.png")


generateTimeHistogram("rsa_low_hw_sign.txt","","")
generateTimeSequence(random,high,low,"seq")

