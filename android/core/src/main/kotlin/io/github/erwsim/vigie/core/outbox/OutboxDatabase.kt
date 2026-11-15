package io.github.erwsim.vigie.core.outbox

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import androidx.room.Upsert

/**
 * One buffered event. `seq` is the contract sequence number and the primary key, so it is
 * unique and ordered. `json` is the complete serialized event, sent verbatim.
 */
@Entity(
    tableName = "outbox",
    indices = [Index(value = ["sev", "seq"]), Index(value = ["ts_ms"])],
)
data class OutboxEntity(
    @PrimaryKey val seq: Long,
    val id: String,
    val type: String,
    val sev: Int,
    @ColumnInfo(name = "ts_ms") val tsMs: Long,
    val json: String,
    @ColumnInfo(name = "size_bytes") val sizeBytes: Int,
)

/** Persistent counters (last assigned `seq`, total dropped events). */
@Entity(tableName = "counters")
data class CounterEntity(
    @PrimaryKey val name: String,
    val value: Long,
)

data class OutboxTotals(
    val count: Long,
    val bytes: Long,
)

data class PurgeCandidate(
    val seq: Long,
    @ColumnInfo(name = "ts_ms") val tsMs: Long,
    @ColumnInfo(name = "size_bytes") val sizeBytes: Int,
)

data class RangeInfo(
    val count: Long,
    @ColumnInfo(name = "oldest") val oldest: Long?,
    @ColumnInfo(name = "newest") val newest: Long?,
    val bytes: Long,
)

@Dao
interface OutboxDao {
    @Insert
    suspend fun insertAll(rows: List<OutboxEntity>)

    @Query("SELECT value FROM counters WHERE name = :name")
    suspend fun counter(name: String): Long?

    @Upsert
    suspend fun setCounter(counter: CounterEntity)

    @Query("SELECT * FROM outbox WHERE sev >= :minSev ORDER BY seq LIMIT :limit")
    suspend fun oldest(limit: Int, minSev: Int): List<OutboxEntity>

    @Query("SELECT * FROM outbox ORDER BY seq DESC LIMIT :limit")
    suspend fun newest(limit: Int): List<OutboxEntity>

    @Query("SELECT COALESCE(SUM(size_bytes), 0) FROM outbox WHERE seq IN (:seqs)")
    suspend fun sizeOf(seqs: List<Long>): Long

    @Query("DELETE FROM outbox WHERE seq IN (:seqs)")
    suspend fun deleteSeqs(seqs: List<Long>): Int

    @Query("SELECT COUNT(*) AS count, COALESCE(SUM(size_bytes), 0) AS bytes FROM outbox")
    suspend fun totals(): OutboxTotals

    @Query("SELECT COUNT(*) FROM outbox WHERE sev >= :minSev")
    suspend fun countMinSev(minSev: Int): Long

    @Query("SELECT MIN(ts_ms) FROM outbox")
    suspend fun oldestTs(): Long?

    @Query(
        "SELECT COUNT(*) AS count, MIN(ts_ms) AS oldest, MAX(ts_ms) AS newest, " +
            "COALESCE(SUM(size_bytes), 0) AS bytes FROM outbox WHERE ts_ms < :cutoff",
    )
    suspend fun olderThan(cutoff: Long): RangeInfo

    @Query("DELETE FROM outbox WHERE ts_ms < :cutoff")
    suspend fun deleteOlderThan(cutoff: Long): Int

    /** Purge order: lowest severity first, then oldest first. */
    @Query("SELECT seq, ts_ms, size_bytes FROM outbox ORDER BY sev, seq LIMIT :limit OFFSET :offset")
    suspend fun purgeCandidates(limit: Int, offset: Int): List<PurgeCandidate>

    @Query("DELETE FROM outbox")
    suspend fun clear()
}

@Database(entities = [OutboxEntity::class, CounterEntity::class], version = 1, exportSchema = true)
abstract class OutboxDatabase : RoomDatabase() {
    abstract fun outboxDao(): OutboxDao

    companion object {
        const val NAME = "vigie-outbox.db"
    }
}
