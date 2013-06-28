library("ggplot2")
library("reshape2")

walk_rtts <- read.table("walk_rtts.txt", quote="\"")
p <- ggplot(walk_rtts, aes(factor(V2), V3))
p <- p + geom_boxplot(aes(fill=factor(V1)))
p <- p + coord_flip()
p <- p + labs(title="Bootstrap server response time", 
              x="Server address", 
              y="Round-trip time",
              colour="Server hostname")

png(filename="walk_rtts.png",
    units="px", width=1024, height=512)
p
dev.off()

summary <- read.table("summary.txt", quote="\"")
p <- ggplot(summary, aes(factor(V2), V3))
p <- p + geom_bar(aes(fill=factor(V1)))
p <- p + coord_flip()
p <- p + labs(title="Bootstrap server walk request success", 
              x="Server address",
              y="Successfull walks", 
              colour="Server hostname")

png(filename="summary.png",
    units="px", width=1024, height=512)
p
dev.off()
