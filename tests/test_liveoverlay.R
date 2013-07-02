library("ggplot2")
library("reshape2")

my_graph <- function(name, hash) {
 connections <- read.table(paste(hash, "_connections.txt", sep=""), header=T, quote="\"")
 mconnections <- melt(connections, id=c("TIME"))

 p <- ggplot(connections, aes(TIME, VERIFIED_CANDIDATES))
 p <- p + geom_point()
 p <- p + labs(title=paste(name, " overlay health\n[", hash, "]", sep=""),
               x="Time (seconds)",
               y="Verified candidates")

 ggsave(file=paste(hash, "_connections.png", sep=""),
        width=8, height=6, dpi=100)
}

my_graph("All-channel community", "8164f55c2f828738fa779570e4605a81fec95c9d")
my_graph("Barter community", "4fe1172862c649485c25b3d446337a35f389a2a2")
my_graph("Search community", "2782dc9253cef6cc9272ee8ed675c63743c4eb3a")

q(save="no")
