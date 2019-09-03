package net.corda.djvm.execution;

import net.corda.djvm.TestBase;
import net.corda.djvm.JavaAnnotation;
import net.corda.djvm.WithJava;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.function.Function;

import static net.corda.djvm.SandboxType.JAVA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

class AnnotatedJavaClassTest extends TestBase {
    AnnotatedJavaClassTest() {
        super(JAVA);
    }

    @Test
    void testSandboxAnnotation() {
        assertThat(UserJavaData.class.getAnnotation(JavaAnnotation.class)).isNotNull();

        parentedSandbox(ctx -> {
            try {
                Class<?> sandboxClass = loadClass(ctx, UserJavaData.class.getName()).getType();
                @SuppressWarnings("unchecked")
                Class<? extends Annotation> sandboxAnnotation
                    = (Class<? extends Annotation>) loadClass(ctx, JavaAnnotation.class.getName()).getType();
                Annotation annotationValue = sandboxClass.getAnnotation(sandboxAnnotation);
                assertThat(annotationValue).isNotNull();
                assertThat(annotationValue.toString())
                    .isEqualTo("@sandbox.net.corda.djvm.JavaAnnotation(value=Hello Java!)");
            } catch (Exception e) {
                fail(e);
            }
            return null;
        });
    }

    @Test
    void testAnnotationInsideSandbox() {
        parentedSandbox(ctx -> {
            try {
                SandboxExecutor<String, String> executor = new DeterministicSandboxExecutor<>(ctx.getConfiguration());
                ExecutionSummaryWithResult<String> success = WithJava.run(executor, ReadAnnotation.class, null);
                assertThat(success.getResult())
                    .isEqualTo("@sandbox.net.corda.djvm.JavaAnnotation(value=Hello Java!)");
            } catch (Exception e) {
                fail(e);
            }
            return null;
        });
    }

    public static class ReadAnnotation implements Function<String, String> {
        @Override
        public String apply(String input) {
            JavaAnnotation value = UserJavaData.class.getAnnotation(JavaAnnotation.class);
            return value == null ? null : value.toString();
        }
    }

    @SuppressWarnings("WeakerAccess")
    @JavaAnnotation("Hello Java!")
    static class UserJavaData {}
}