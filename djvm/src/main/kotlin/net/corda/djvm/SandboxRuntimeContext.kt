package net.corda.djvm

import net.corda.djvm.costing.RuntimeCostSummary
import net.corda.djvm.execution.ExecutionProfile
import net.corda.djvm.rewiring.SandboxClassLoader
import java.security.AccessController.doPrivileged
import java.security.PrivilegedAction
import java.util.function.Consumer

/**
 * The context in which a sandboxed operation is run.
 *
 * @property configuration The configuration of the sandbox.
 */
class SandboxRuntimeContext(val configuration: SandboxConfiguration) {

    /**
     * The class loader to use inside the sandbox.
     */
    val classLoader: SandboxClassLoader = doPrivileged(PrivilegedAction {
        SandboxClassLoader.createFor(configuration)
    })

    /**
     * A summary of the currently accumulated runtime costs (for, e.g., memory allocations, invocations, etc.).
     */
    val runtimeCosts = RuntimeCostSummary(configuration.executionProfile ?: ExecutionProfile.UNLIMITED)

    private val hashCodes: MutableMap<Int, Int> = mutableMapOf()
    private var objectCounter: Int = 0

    // TODO Instead of using a magic offset below, one could take in a per-context seed
    fun getHashCodeFor(nativeHashCode: Int): Int {
        return hashCodes.computeIfAbsent(nativeHashCode) { ++objectCounter + MAGIC_HASH_OFFSET }
    }

    private val internStrings: MutableMap<String, Any> = mutableMapOf()

    fun intern(key: String, value: Any): Any {
        return internStrings.computeIfAbsent(key) { value }
    }

    /**
     * Run a set of actions within the provided sandbox context.
     */
    fun use(action: Consumer<SandboxRuntimeContext>) {
        instance = this
        try {
            action.accept(this)
        } finally {
            threadLocalContext.remove()
            doPrivileged(PrivilegedAction { classLoader.close() })
        }
    }

    companion object {

        private val threadLocalContext = ThreadLocal<SandboxRuntimeContext?>()
        private const val MAGIC_HASH_OFFSET = 0xfed_c0de

        /**
         * When called from within a sandbox, this returns the context for the current sandbox thread.
         */
        @JvmStatic
        var instance: SandboxRuntimeContext
            get() = threadLocalContext.get()
                    ?: throw IllegalStateException("SandboxContext has not been initialized before use")
            private set(value) {
                threadLocalContext.set(value)
            }

    }

}
