package org.glassfish.epicyro.quarkus.deployment;

import org.glassfish.epicyro.quarkus.runtime.EpicyroConfig;
import org.glassfish.epicyro.quarkus.runtime.EpicyroHttpAuthenticationMechanism;
import org.glassfish.epicyro.quarkus.runtime.EpicyroServletExtension;
import org.glassfish.epicyro.quarkus.runtime.EpicyroServletHttpSecurityPolicy;

import java.util.ArrayList;
import java.util.List;

import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.ExcludedTypeBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.IndexDependencyBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBundleBuildItem;
import io.quarkus.undertow.deployment.ServletExtensionBuildItem;
import io.quarkus.undertow.runtime.ServletHttpSecurityPolicy;

class EpicyroProcessor {

    private static final String FEATURE = "epicyro";

    /**
     * Types Jakarta Authentication and Epicyro create from a class name: the factory and the providers. Modules are only
     * created by name from GlassFish's module configuration, which doesn't apply here.
     */
    private static final List<DotName> CREATED_BY_NAME = List.of(
            DotName.createSimple("jakarta.security.auth.message.config.AuthConfigFactory"),
            DotName.createSimple("jakarta.security.auth.message.config.AuthConfigProvider"));

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    ServletExtensionBuildItem servletExtension(EpicyroConfig config) {
        // Undertow deploys during static init, so the configuration is passed in at build time
        EpicyroServletExtension servletExtension = new EpicyroServletExtension();
        servletExtension.setVirtualServerName(config.virtualServerName().orElse(null));
        return new ServletExtensionBuildItem(servletExtension);
    }

    @BuildStep
    AdditionalBeanBuildItem beans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(EpicyroHttpAuthenticationMechanism.class, EpicyroServletHttpSecurityPolicy.class)
                .setUnremovable()
                .build();
    }

    /**
     * Quarkus' servlet policy enforces servlet constraints before the ServerAuthModule runs; it's replaced by
     * {@link EpicyroServletHttpSecurityPolicy}, so that Undertow enforces them after authentication.
     */
    @BuildStep
    ExcludedTypeBuildItem excludeServletHttpSecurityPolicy() {
        return new ExcludedTypeBuildItem(ServletHttpSecurityPolicy.class.getName());
    }

    /**
     * {@code Subject.getPrincipals(Class)}, used to get the caller from the Subject the ServerAuthModule filled, loads this
     * JDK bundle for its error messages, also when there is no error.
     */
    @BuildStep
    NativeImageResourceBundleBuildItem securityResourceBundle() {
        return new NativeImageResourceBundleBuildItem("sun.security.util.resources.security");
    }

    /** Index Epicyro, so its own factories and providers are found in {@link #createdByName}. */
    @BuildStep
    IndexDependencyBuildItem indexEpicyro() {
        return new IndexDependencyBuildItem("org.glassfish.epicyro", "epicyro");
    }

    /**
     * {@code AuthConfigFactory.getFactory()} and {@code AuthConfigFactory.registerConfigProvider(String className, ...)}
     * create factories and providers from a class name. Register the constructors of all of them, from Epicyro and the
     * application, so that works in a native executable as well.
     */
    @BuildStep
    ReflectiveClassBuildItem createdByName(CombinedIndexBuildItem combinedIndex) {
        IndexView index = combinedIndex.getIndex();
        List<String> classNames = new ArrayList<>();
        for (DotName type : CREATED_BY_NAME) {
            for (ClassInfo classInfo : index.getAllKnownImplementations(type)) {
                if (!classInfo.isInterface() && !classInfo.isAbstract()) {
                    classNames.add(classInfo.name().toString());
                }
            }
            for (ClassInfo classInfo : index.getAllKnownSubclasses(type)) {
                if (!classInfo.isAbstract()) {
                    classNames.add(classInfo.name().toString());
                }
            }
        }
        return ReflectiveClassBuildItem.builder(classNames.toArray(String[]::new))
                .constructors()
                .reason(getClass().getName())
                .build();
    }
}
