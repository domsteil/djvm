package net.corda.djvm.rewiring

import net.corda.djvm.SandboxConfiguration
import net.corda.djvm.analysis.AnalysisContext
import net.corda.djvm.analysis.ClassAndMemberVisitor.Companion.API_VERSION
import net.corda.djvm.code.ClassMutator
import net.corda.djvm.code.EmitterModule
import net.corda.djvm.code.emptyAsNull
import net.corda.djvm.references.Member
import net.corda.djvm.references.MethodBody
import net.corda.djvm.source.SourceClassLoader
import net.corda.djvm.utilities.loggerFor
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassReader.SKIP_FRAMES
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter.COMPUTE_FRAMES
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes.ACC_ABSTRACT

/**
 * Functionality for rewriting parts of a class as it is being loaded.
 *
 * @property configuration The configuration of the sandbox.
 * @property classLoader The class loader used to load the source classes that are to be rewritten.
 */
open class ClassRewriter(
        private val configuration: SandboxConfiguration,
        private val classLoader: SourceClassLoader
) {
    private val analysisConfig = configuration.analysisConfiguration

    /**
     * Process class and allow user to rewrite parts/all of its content through provided hooks.
     *
     * @param reader The reader providing the byte code for the desired class.
     * @param context The context in which the class is being analyzed and processed.
     */
    fun rewrite(reader: ClassReader, context: AnalysisContext): ByteCode {
        logger.debug("Rewriting class {}...", reader.className)
        val writer = SandboxClassWriter(reader, classLoader, analysisConfig, options = COMPUTE_FRAMES)
        val classRemapper = SandboxClassRemapper(
            ClassExceptionRemapper(SandboxStitcher(writer)),
            analysisConfig
        )
        val visitor = ClassMutator(
            classRemapper,
            analysisConfig,
            configuration.definitionProviders,
            configuration.emitters
        )
        visitor.analyze(reader, context, options = SKIP_FRAMES)
        return ByteCode(writer.toByteArray(), visitor.hasBeenModified)
    }

    private companion object {
        private val logger = loggerFor<ClassRewriter>()
    }

    /**
     * Extra visitor that is applied after [SandboxRemapper]. This "stitches" the original
     * unmapped interface as a super-interface of the mapped version, as well as adding
     * or replacing any extra methods that are needed.
     */
    private inner class SandboxStitcher(parent: ClassVisitor)
        : ClassVisitor(API_VERSION, parent)
    {
        private val extraMethods = mutableListOf<Member>()

        override fun visit(version: Int, access: Int, className: String, signature: String?, superName: String?, interfaces: Array<String>?) {
            val stitchedInterfaces = analysisConfig.stitchedInterfaces[className]?.let { methods ->
                extraMethods += methods
                arrayOf(*(interfaces ?: emptyArray()), analysisConfig.classResolver.reverse(className))
            } ?: interfaces

            analysisConfig.stitchedClasses[className]?.also { methods ->
                extraMethods += methods
            }

            super.visit(version, access, className, signature, superName, stitchedInterfaces)
        }

        override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
            return if (extraMethods.isEmpty()) {
                super.visitMethod(access, name, descriptor, signature, exceptions)
            } else {
                val idx = extraMethods.indexOfFirst { it.memberName == name && it.descriptor == descriptor && it.genericsDetails.emptyAsNull == signature }
                if (idx != -1) {
                    val replacement = extraMethods.removeAt(idx)
                    if (replacement.body.isNotEmpty() || (access and ACC_ABSTRACT) != 0) {
                        // Replace an existing method, or delete it entirely if
                        // the replacement has no method body and isn't abstract.
                        super.visitMethod(access, name, descriptor, signature, exceptions)?.run {
                            writeMethodBody(this, replacement.body)
                        }
                    }
                    null
                } else {
                    super.visitMethod(access, name, descriptor, signature, exceptions)
                }
            }
        }

        override fun visitEnd() {
            for (method in extraMethods) {
                with(method) {
                    super.visitMethod(access, memberName, descriptor, genericsDetails.emptyAsNull, exceptions.toTypedArray())?.run {
                        writeMethodBody(this, body)
                    }
                }
            }
            extraMethods.clear()
            super.visitEnd()
        }

        private fun writeMethodBody(mv: MethodVisitor, body: List<MethodBody>) {
            mv.visitCode()
            EmitterModule(mv, analysisConfig).writeByteCode(body)
            mv.visitMaxs(-1, -1)
            mv.visitEnd()
        }
    }

    /**
     * Map exceptions in method signatures to their sandboxed equivalents.
     */
    private inner class ClassExceptionRemapper(parent: ClassVisitor) : ClassVisitor(API_VERSION, parent) {
        override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor? {
            val mappedExceptions = exceptions?.map(analysisConfig.exceptionResolver::getThrowableOwnerName)?.toTypedArray()
            return super.visitMethod(access, name, descriptor, signature, mappedExceptions)?.let {
                MethodExceptionRemapper(it)
            }
        }
    }

    /**
     * Map exceptions in method try-catch blocks to their sandboxed equivalents.
     */
    private inner class MethodExceptionRemapper(parent: MethodVisitor) : MethodVisitor(API_VERSION, parent) {
        override fun visitTryCatchBlock(start: Label, end: Label, handler: Label, exceptionType: String?) {
            val mappedExceptionType = exceptionType?.let(analysisConfig.exceptionResolver::getThrowableOwnerName)
            super.visitTryCatchBlock(start, end, handler, mappedExceptionType)
        }
    }
}
