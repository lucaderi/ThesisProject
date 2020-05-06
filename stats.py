
# https://web.stanford.edu/class/archive/anthsci/anthsci192/anthsci192.1064/handouts/calculating%20percentiles.pdf
# https://www.statisticshowto.com/probability-and-statistics/percentiles-rank-range/
import math


def mean(list):
    sum = 0
    for el in list:
        sum += el
    return (sum / len(list))

def std_dev(list, mean):
    sum = 0
    for el in list:
        sum += ((el - mean)**2)
    stddev = math.sqrt(sum/(len(list)-1))
    return stddev



def percentile(list, perc):

    #sort the list
    sortedList = sorted(list)

    # calculate the index of the percentile on the list
    index = len(list) * (perc/100)

    rounded_index = int(index + 0.5)

    return list[rounded_index - 1]


def quartiles(list):
    q1 = percentile(list, 25)
    q2 = percentile(list, 50)
    q3 = percentile(list, 75)
    quartiles = [q1, q2, q3]
    return q1, q2, q3


def percentile_range(list, p1, p2):
    if p1 > p2:
        raise ValueError("first percentile must be smaller than last one")
    first_percentile = percentile(list, p1)
    second_percentile = percentile(list, p2)
    return second_percentile - first_percentile


def outlier_range(list):

    # compute quartiles
    sortedList = sorted(list)
    q1, q2, q3 = quartiles(sortedList)

    iqr = q3 - q1
    k = 1.5

    # outlier lower fence
    lower_fence = q1 - k*iqr

    # outlier upper fence
    upper_fence = q3 + k*iqr

    return lower_fence, upper_fence


