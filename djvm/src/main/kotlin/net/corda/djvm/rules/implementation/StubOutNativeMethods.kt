package net.corda.djvm.rules.implementation

import net.corda.djvm.analysis.AnalysisRuntimeContext
import net.corda.djvm.code.EmitterModule
import net.corda.djvm.code.MemberDefinitionProvider
import net.corda.djvm.references.Member
import org.objectweb.asm.Opcodes.*
import java.lang.reflect.Modifier

/**
 * Rule that replaces a native method with a stub that throws an exception.
 */
object StubOutNativeMethods : MemberDefinitionProvider {

    override fun define(context: AnalysisRuntimeContext, member: Member) = when {
        member.isMethod && isNative(member) -> member.copy(
            access = member.access and ACC_NATIVE.inv(),
            body = member.body + if (isForStubbing(member)) ::writeStubMethodBody else MemberRuleEnforcer(member)::forbidNativeMethod
        )
        else -> member
    }

    private fun writeStubMethodBody(emitter: EmitterModule): Unit = with(emitter) {
        returnVoid()
    }

    private fun isForStubbing(member: Member): Boolean = member.descriptor == "()V" && member.memberName == "registerNatives"

    private fun isNative(member: Member): Boolean = Modifier.isNative(member.access)
}
