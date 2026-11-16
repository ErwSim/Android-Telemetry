package io.github.erwsim.vigie.policy.logs

/** A group of identical log entries: the first one, how many, and the time of the last one. */
data class Aggregated<T>(val first: T, val count: Int, val firstMs: Long, val lastMs: Long, val members: List<T>)

/**
 * Counts identical entries ([key]) whose timestamps fall in the same window of [windowMs]
 * (aligned on multiples of the window). Order of the output: order of first appearance. With
 * `windowMs <= 0` nothing is merged. Pure (tested on the JVM).
 */
fun <T> aggregateByWindow(items: List<T>, windowMs: Long, timeOf: (T) -> Long, key: (T) -> Any): List<Aggregated<T>> {
    if (windowMs <= 0) return items.map { Aggregated(it, 1, timeOf(it), timeOf(it), listOf(it)) }
    val groups = LinkedHashMap<Pair<Any, Long>, MutableList<T>>()
    for (item in items) {
        val bucket = Math.floorDiv(timeOf(item), windowMs)
        groups.getOrPut(key(item) to bucket) { ArrayList() } += item
    }
    return groups.values.map { members ->
        val times = members.map(timeOf)
        Aggregated(members.first(), members.size, times.min(), times.max(), members)
    }
}
