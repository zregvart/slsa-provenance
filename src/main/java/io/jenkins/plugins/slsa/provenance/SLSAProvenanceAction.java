/*
 * Copyright (C) Jenkins plugin contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package io.jenkins.plugins.slsa.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.Action;
import hudson.model.Run;
import hudson.util.LogTaskListener;
import io.github.intoto.dsse.helpers.SimpleECDSASigner;
import io.github.intoto.exceptions.InvalidModelException;
import io.github.intoto.helpers.IntotoHelper;
import io.github.intoto.models.Statement;
import io.github.intoto.models.Subject;
import io.github.intoto.slsa.models.v1.BuildDefinition;
import io.github.intoto.slsa.models.v1.Builder;
import io.github.intoto.slsa.models.v1.Provenance;
import io.github.intoto.slsa.models.v1.RunDetails;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.ArtifactManager;
import jenkins.model.RunAction2;
import jenkins.util.BuildListenerAdapter;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.output.NullOutputStream;
import org.jenkinsci.plugins.workflow.actions.WorkspaceAction;
import org.jenkinsci.plugins.workflow.graph.FlowGraphWalker;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.kohsuke.stapler.export.DataWriter;
import org.kohsuke.stapler.export.ExportConfig;
import org.kohsuke.stapler.export.Flavor;
import org.kohsuke.stapler.export.ModelBuilder;

public final class SLSAProvenanceAction implements RunAction2 {

    private Run<?, ?> run;

    private SLSAProvenanceAction() {}

    public static Action record(final Run<?, ?> run) {
        final var artifactManager = run.getArtifactManager();
        final var artifacts = run.getArtifacts();
        if (artifacts.isEmpty()) {
            return null;
        }

        final var workspace = workspaceFor(run);

        for (final var artifact : artifacts) {
            final var envelope = createEnvelopeFor(run, artifact);

            final var attestationName = artifact.getFileName() + ".attestation.json";
            final var attestation = new FilePath(workspace, attestationName);

            final Launcher launcher;
            try {
                launcher = attestation.createLauncher(new LogTaskListener(Logger.getAnonymousLogger(), Level.FINE));
            } catch (final IOException | InterruptedException e) {
                throw new RuntimeException(e);
            }

            try {
                attestation.write(envelope, StandardCharsets.UTF_8.name());

                artifactManager.archive(
                        attestation.getParent(),
                        launcher,
                        new BuildListenerAdapter(launcher.getListener()),
                        Map.of(attestationName, attestationName));
            } catch (final IOException | InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        return new SLSAProvenanceAction();
    }

    private static FilePath workspaceFor(final Run<?, ?> run) {
        if (run instanceof AbstractBuild) {
            return ((AbstractBuild<?, ?>) run).getWorkspace();
        } else if (run instanceof WorkflowRun) {
            final var execution = ((WorkflowRun) run).getExecution();
            if (execution == null) {
                throw new IllegalStateException("no execution found for the given WorkflowRun");
            }
            final var walker = new FlowGraphWalker(execution);
            for (final var node : walker) {
                final var action = node.getAction(WorkspaceAction.class);
                if (action != null) {
                    return action.getWorkspace();
                }
            }
        }

        throw new IllegalStateException("no workspace found for the given Run");
    }

    private static String createEnvelopeFor(final Run<?, ?> run, final Run<?, ?>.Artifact artifact) {
        final var predicate = new Provenance();

        predicate.setBuildDefinition(buildDefinitionOf(run));

        predicate.setRunDetails(runDetails());

        final var statement = new Statement();
        statement.setSubject(List.of(subjectOf(run.getArtifactManager(), artifact)));
        statement.setPredicate(predicate);
        try {
            return IntotoHelper.produceIntotoEnvelopeAsJson(statement, signer(), false);
        } catch (final InvalidModelException | IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static SimpleECDSASigner signer() throws NoSuchAlgorithmException {
        final var generator = KeyPairGenerator.getInstance("EC");
        final var keyPair = generator.generateKeyPair();
        return new SimpleECDSASigner(keyPair.getPrivate(), "something");
    }

    private static RunDetails runDetails() {
        final var runDetails = new RunDetails();
        final var builder = new Builder();
        builder.setId("https://jenkins.io/something");
        runDetails.setBuilder(builder);
        return runDetails;
    }

    private static BuildDefinition buildDefinitionOf(final Run<?, ?> r) {
        final var buildDefinition = new BuildDefinition();
        buildDefinition.setBuildType("https://jenkins.io/something");
        final JsonNode runJSON;
        try {
            final var config = new ExportConfig().withFlavor(Flavor.JSON);
            final var stringWriter = new StringWriter();
            final DataWriter dataWriter;
            dataWriter = Flavor.JSON.createDataWriter(r, stringWriter, config);
            @SuppressWarnings({"unchecked", "rawtypes"})
            final var clazz = (Class<Run>) r.getClass();
            final var model = new ModelBuilder().get(clazz);
            model.writeTo(r, dataWriter);

            runJSON = new ObjectMapper().readTree(stringWriter.toString());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
        buildDefinition.setExternalParameters(Map.of("run", runJSON));
        return buildDefinition;
    }

    private static Subject subjectOf(final ArtifactManager artifactManager, final Run<?, ?>.Artifact artifact) {
        final MessageDigest sha256 = messageDigest();

        final var artifactFile = artifactManager.root().child(artifact.relativePath);
        final byte[] digest;
        try (final var in = new DigestInputStream(artifactFile.open(), sha256)) {
            in.transferTo(NullOutputStream.INSTANCE);
            digest = sha256.digest();
            sha256.reset();
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }

        final var subject = new Subject();
        subject.setName(artifact.getFileName());
        subject.setDigest(Map.of("sha256", Hex.encodeHexString(digest)));

        return subject;
    }

    private static MessageDigest messageDigest() {
        final MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA256");
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return sha256;
    }

    @Override
    public String getIconFileName() {
        return "/plugin/slsa-provenance/icons/logo-mono.svg";
    }

    @Override
    public String getDisplayName() {
        return Messages.SLSAProvenanceAction_DisplayName();
    }

    @Override
    public String getUrlName() {
        return "provenance";
    }

    @Override
    public void onAttached(final Run<?, ?> r) {
        run = r;
    }

    @Override
    public void onLoad(final Run<?, ?> r) {}

    public Run<?, ?> getRun() {
        return run;
    }

    @SuppressWarnings("unused")
    public Map<String, String> getAttestations() {
        final var artifactManager = run.getArtifactManager();
        final var attestations = new HashMap<String, String>();
        for (final var artifact : run.getArtifacts()) {
            if (artifact.getFileName().endsWith(".attestation.json")) {
                final var artifactFile = artifactManager.root().child(artifact.relativePath);
                try (final var in = artifactFile.open()) {
                    final var payload = Base64.getDecoder()
                            .decode(new ObjectMapper()
                                    .readTree(in)
                                    .get("payload")
                                    .asText());
                    attestations.put(
                            artifact.getFileName(),
                            new ObjectMapper().readTree(payload).toPrettyString());
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        return attestations;
    }
}
