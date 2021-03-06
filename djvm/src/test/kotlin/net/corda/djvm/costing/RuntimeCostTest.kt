package net.corda.djvm.costing

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.jupiter.api.Test
import java.util.function.Function
import kotlin.concurrent.thread

class RuntimeCostTest {

    @Test
    fun `can increment cost`() {
        val cost = RuntimeCost(10, Function { "failed" })
        cost.increment()
        assertThat(cost.value).isEqualTo(1)
    }

    @Test
    fun `cannot increment cost beyond threshold`() {
        thread(name = "Foo") {
            val cost = RuntimeCost(10, Function { "failed in ${it.name}" })
            assertThatExceptionOfType(ThresholdViolationError::class.java)
                    .isThrownBy { cost.increment(11) }
                    .withMessage("failed in Foo")
            assertThat(cost.value).isEqualTo(11)
        }.join()
    }

}
