source("functions.r")

generateTimeHistogram("rsa_high_hw.txt",
                      "Histogram of time necessary for decryption (high HW exp, fixed message)",
                      "rsa_high_hw_exp_dec.png")

generateTimeHistogram("rsa_random_exp_dec.txt",
                      "Histogram of time necessary for decryption (random exp, fixed message)",
                      "rsa_random_exp_dec.png")

generateTimeHistogram("rsa_random_msg_dec.txt",
                      "Histogram of time necessary for decryption (random messages, fixed exponent)",
                      "rsa_random_messages_dec.png")

generateTimeHistogram("rsa_random_message_sig.txt",
                      "Histogram of time necessary for signature (random messages, fixed exponent)",
                      "rsa_random_messages_sig.png")

generateTimeHistogram("rsa_random_exp_sig.txt",
                      "Histogram of time necessary for signature (random exponent, fixed message)",
                      "rsa_random_exp_sig.png")



data <- read.csv2("rsa_high_hw.txt", header=T)
times <- as.numeric(levels(data$TIME))[data$TIME]
times <- times[times < max(times)] / 1000000
timesSorted <- head(sort(times),19800)
hist(timesSorted, col="lightblue", main = "Histogram of time necessary to decrypt with high HW exp", xlab="time in ms", ylab="occurances")
save.image("rsa_high_hw_encryption_hist.jpg")

plot(times, type="h", col="blue")


data<- read.csv2("ecc_random_exp.txt", header=T)
times <- as.numeric(levels(data$TIME))[data$TIME]
times <- times[times < max(times)] / 1000000
timesSorted <- head(sort(times),19800)
hist(timesSorted, col="lightblue", main = "Histogram of time necessary to decrypt with high HW exp", xlab="time in ms", ylab="occurances",breaks="fd")
save.image("rsa_high_hw_encryption_hist.jpg")

plot(times, type="h", col="blue")

data<- read.csv2("ecc_random_messages.txt", header=T)
times <- as.numeric(levels(data$TIME))[data$TIME]
times <- times[times < max(times)] / 1000000
timesSorted <- head(sort(times),19900)
hist(timesSorted, col="lightblue", main = "Histogram of time necessary to decrypt with high HW exp", xlab="time in ms", ylab="occurances",breaks="fd")
save.image("rsa_high_hw_encryption_hist.jpg")

plot(times, type="h", col="blue")


