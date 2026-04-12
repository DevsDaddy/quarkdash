/**
 * JSDoc Util to change headers
 *
 * @author                Elijah Rastorguev
 * @version               1.0.0
 * @build                 1004
 * @git                   https://github.com/devsdaddy/bitwarp
 * @license               MIT
 * @updated               12.04.2026
 */
import { Project, SyntaxKind } from "ts-morph";
import { execSync } from "child_process";

/**
 * JSDoc Change Util
 */
async function updateJSDocInChangedFiles() {
    // Get all changed files via GIT
    const changedFiles = execSync("git diff --name-only").toString().trim().split("\n").filter(file => file.endsWith(".ts"));

    if (changedFiles.length === 0) {
        console.log("No changes found in project.");
        return;
    }

    console.log(`Found changed files: ${changedFiles.length}`);

    // Create ts-morph project
    const project = new Project({
        tsConfigFilePath: "tsconfig.json",
        skipAddingFilesFromTsConfig: true, // Only changed
    });

    // Add changed files
    changedFiles.forEach(file => project.addSourceFileAtPath(file));

    // Prepare date for @updated
    const today = new Date();
    const formattedDate = `${today.getDate().toString().padStart(2, '0')}.${(today.getMonth() + 1).toString().padStart(2, '0')}.${today.getFullYear()}`;
    let filesUpdatedCount = 0;

    // Change every changed file
    for (const sourceFile of project.getSourceFiles()) {
        let fileWasModified = false;
        const jsdocs = sourceFile.getDescendantsOfKind(SyntaxKind.JSDoc);

        for (const jsdoc of jsdocs) {
            const buildTag = jsdoc.getTags().find(tag => tag.getTagName() === "build");
            const updatedTag = jsdoc.getTags().find(tag => tag.getTagName() === "updated");

            // Work with @build
            if (buildTag) {
                const commentText = buildTag.getCommentText();
                if (commentText) {
                    const currentBuild = parseInt(commentText.trim(), 10);
                    if (!isNaN(currentBuild)) {
                        const newBuild = currentBuild + 1;
                        buildTag.replaceWithText(`@build                 ${newBuild}`);
                        fileWasModified = true;
                        console.log(`  -> File: ${sourceFile.getFilePath()}, @build updated from ${currentBuild} to ${newBuild}`);
                    }
                }
            }

            // Work with @updated
            if (updatedTag) {
                updatedTag.replaceWithText(`@updated               ${formattedDate}`);
                fileWasModified = true;
                console.log(`  -> File: ${sourceFile.getFilePath()}, @updated changed to ${formattedDate}`);
            }
        }

        // Save modified file
        if (fileWasModified) {
            await sourceFile.save();
            filesUpdatedCount++;
        }
    }

    console.log(`Done! Updated files: ${filesUpdatedCount}.`);
}

// Update JSDoc in Changed Files
updateJSDocInChangedFiles().catch(console.error);