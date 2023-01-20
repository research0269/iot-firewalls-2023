library(ggplot2)
library(dplyr)
library(broom)
library(ggpubr)
library(magrittr)
library(MASS)
library(xtable)

geo_lm <- function(fp) {
  data <- read.csv(fp)
  
  data$train_region <- as.factor(data$train_region)
  data$test_region <- as.factor(data$test_region)
  data$product <- as.factor(data$product)
  data$is_same_region <- as.factor(data$is_same_region)
  levels(data$is_same_region) <- c("True", "False")
  
  result <-lm(transferability ~ train_region + test_region + is_same_region + train_region * test_region + product + log(train_flow_size), data=data)
  
  step.model <- stepAIC(result, direction = "both")
  step.table <- xtable(summary(step.model), digits = 3)
  print(summary(step.model))
  print(step.table)
}

print("IP")
geo_lm("../data/geo_eval/remote_ip.csv")
print("Subnet")
geo_lm("../data/geo_eval/subnet_24.csv")
print("BGP Prefix")
geo_lm("../data/geo_eval/network.csv")
print("ASN")
geo_lm("../data/geo_eval/asn.csv")

print("Domain")
geo_lm("../data/geo_eval/short_domain.csv")
print("Hostname")
geo_lm("../data/geo_eval/short_hostname.csv")
print("Hostname Pattern")
geo_lm("../data/geo_eval/hostname_pattern.csv")