package id.my.khuirulhuda.lib.liteapkparser

interface LiteApkParserLogger {
    fun d(tag: String, msg: String)
    fun e(tag: String, msg: String, throwable: Throwable? = null)
}

internal object Logger {
    var instance: LiteApkParserLogger? = object : LiteApkParserLogger {
        override fun d(tag: String, msg: String) {
            println("[$tag] $msg")
        }
        override fun e(tag: String, msg: String, throwable: Throwable?) {
            System.err.println("[$tag] ERROR: $msg")
            throwable?.printStackTrace()
        }
    }

    fun d(tag: String, msg: String) {
        instance?.d(tag, msg)
    }

    fun e(tag: String, msg: String, throwable: Throwable? = null) {
        instance?.e(tag, msg, throwable)
    }
}
