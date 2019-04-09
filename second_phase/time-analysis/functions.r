rsa_graphs <- function(file1, file2, file3, titleString, output) {
  data1 <- read.csv2(file1, header=T)
  data2 <- read.csv2(file2, header=T)
  data3 <- read.csv2(file3, header=T)
  
  times1 <- as.numeric(levels(data1$TIME))[data1$TIME]
  times2 <- as.numeric(levels(data2$TIME))[data2$TIME]
  times3 <- as.numeric(levels(data3$TIME))[data3$TIME]
  
  times1 <- times1[times1 < max(times1)] / 1000000
  times2 <- times2[times2 < max(times2)] / 1000000
  times3 <- times3[times3 < max(times3)] / 1000000
  
  timeSorted1 <- head(sort(times1),length(times1)*0.99)
  timeSorted2 <- head(sort(times2), length(times2)*0.99)
  timeSorted3 <- head(sort(times3), length(times3)*0.99)
  
  p1 <- hist(timeSorted1, breaks=288)
  p2 <- hist(timeSorted2, breaks=288)
  p3 <- hist(timeSorted3, breaks=288)
  
  
  plot(p1, col=rgb(0,0,1,1/4), main = titleString, xlab="time in ms", ylim=c(0, 8000), xlim = c(13.09,13.22))
  plot(p2, col=rgb(0,1,0,1/4), add=T)
  plot(p3, col=rgb(1,0,0,1/4), add=T)
  legend("topright",c("random","high HW", "low HW"), fill=c(rgb(0,0,1,1/4), rgb(0,1,0,1/4), rgb(1,0,0,1/4)))
}

ecc_graphs <- function(file1, file2, file3, titleString, output) {
  file1 <- "ecc_random_exp.txt"
  file2 <- "ecc_large_exponent.txt"
  file3 <- "ecc_short_exponent.txt"
  
  data1 <- read.csv2(file1, header=T)
  data2 <- read.csv2(file2, header=T)
  data3 <- read.csv2(file3, header=T)
  
  times1 <- as.numeric(levels(data1$TIME))[data1$TIME]
  times2 <- as.numeric(levels(data2$TIME))[data2$TIME]
  times3 <- as.numeric(levels(data3$TIME))[data3$TIME]
  
  times1 <- times1[times1 < max(times1)] / 1000000
  times2 <- times2[times2 < max(times2)] / 1000000
  times3 <- times3[times3 < max(times3)] / 1000000
  
  timeSorted1 <- head(sort(times1),length(times1)*0.99)
  timeSorted2 <- head(sort(times2), length(times2)*0.99)
  timeSorted3 <- head(sort(times3), length(times3)*0.99)
  
  p1 <- hist(timeSorted1, breaks="fd")
  p2 <- hist(timeSorted2, breaks="fd")
  p3 <- hist(timeSorted3, breaks="fd")
  
  
  plot(p1, col=rgb(0,0,1,1/4), main = "titleString", xlab="time in ms", ylim=c(0, 8000), xlim = c(1.47,1.5))
  plot(p2, col=rgb(0,1,0,1/4), add=T)
  plot(p3, col=rgb(1,0,0,1/4), add=T)
  legend("topright",c("random","high HW", "low HW"), fill=c(rgb(0,0,1,1/4), rgb(0,1,0,1/4), rgb(1,0,0,1/4)))
}

generateTimeSequence <- function(file1, file2, file3, titleString) {
  data1 <- read.csv2(file1, header=T)
  data2 <- read.csv2(file2, header=T)
  data3 <- read.csv2(file3, header=T)
  
  times1 <- as.numeric(levels(data1$TIME))[data1$TIME]
  times2 <- as.numeric(levels(data2$TIME))[data2$TIME]
  times3 <- as.numeric(levels(data3$TIME))[data3$TIME]
  
  times1 <- times1[times1 < max(times1)] / 1000000
  times2 <- times2[times2 < max(times2)] / 1000000
  times3 <- times3[times3 < max(times3)] / 1000000
  
  times1 <- c(times1, seq(0,0,length=80000))
  
#  plot(times1, type="h", col=rgb(0,0,1,1/4), xlab="index", ylab="time in ms", main=titleString)
  plot(times2,type="h",col=rgb(0,1,0,1/4))
#  points(times3, type="h", col=rgb(1,0,0,1/4))
#  legend("topright",c("random","high HW", "low HW"), fill=c(rgb(0,0,1,1/4), rgb(0,1,0,1/4), rgb(1,0,0,1/4)))
}

