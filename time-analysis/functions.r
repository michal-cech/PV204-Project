generateTimeHistogram <- function(file, titleString, output) {
  data <- read.csv2(file, header=T)
  times <- as.numeric(levels(data$TIME))[data$TIME]
  times <- times[times < max(times)] / 1000000
  timesSorted <- head(sort(times),19900)
  png(filename=output, width=1024, height=768)
  hist(timesSorted, col="lightblue", main = titleString, xlab="time in ms", ylab="occurances", breaks="fd")
  dev.off()
  
}

generateTimeSequence <- function(file, titleString, output) {
  data <- read.csv2(file, header=T)
  times <- as.numeric(levels(data$TIME))[data$TIME]
  times <- times[times < max(times)] / 1000000
  plot(times, type="h", col="blue", xlab="index", ylab="time in ms", main=titleString)
  save.image(output)
}