library("ggplot2")
library("reshape2")

walk_rtts <- read.table("walk_rtts.txt", header=T, quote="\"")
p <- ggplot(walk_rtts, aes(factor(ADDRESS), RTT))
p <- p + geom_boxplot(aes(fill=factor(HOST_NAME)))
p <- p + coord_flip()
p <- p + labs(title="Bootstrap server response time", 
              x="Server address", 
              y="Round-trip time (seconds)",
              colour="Server hostname")
p
ggsave("walk_rtts.png", width=10, height=6, dpi=100)

summary <- read.table("summary.txt", header=T, quote="\"")
p <- ggplot(summary, aes(factor(ADDRESS), RESPONSES))
p <- p + geom_bar(aes(fill=factor(HOST_NAME)))
p <- p + coord_flip()
p <- p + ylim(0, max(summary$REQUESTS))
p <- p + labs(title=paste("Bootstrap server walk request success\nout of", max(summary$REQUESTS), "requests"),
              x="Server address",
              y="Successfull walks",
              colour="Server hostname")
p
ggsave("summary.png", width=10, height=6, dpi=100)

q(save="no")
