[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManagedResourcesRoot
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($ManagedResourcesRoot)
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Managed resources root is missing: $root"
}
$reparsePoint = Get-ChildItem -LiteralPath $root -Force -Recurse | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
} | Select-Object -First 1
if ($null -ne $reparsePoint) {
    throw "Managed resources contain a reparse point: $($reparsePoint.FullName)"
}

$candidates = @(Get-ChildItem -LiteralPath (Join-Path $root 'acp\codex-acp') -Filter index.js -File -Recurse | Where-Object {
    $_.FullName -match '[\\/]node_modules[\\/]@agentclientprotocol[\\/]codex-acp[\\/]dist[\\/]index\.js$'
})
if ($candidates.Count -ne 1) {
    throw "Expected exactly one managed Codex ACP dist/index.js, found $($candidates.Count)."
}
$indexPath = $candidates[0].FullName
$source = [IO.File]::ReadAllText($indexPath)
$forkMarker = 'AionUI session/fork requires a non-negative _meta.aionui.turnIndex'
$steerMarker = 'AionUI steer requires a non-empty ACP prompt'
$changed = $false
if ($source.Contains($forkMarker)) {
    if (($source.Split($forkMarker).Count - 1) -ne 1) {
        throw 'Managed Codex ACP session-fork patch is duplicated.'
    }
}

function Replace-ExactlyOnce([string]$Text, [string]$Needle, [string]$Replacement, [string]$Label) {
    $count = $Text.Split($Needle).Count - 1
    if ($count -ne 1) {
        throw "Expected exactly one Codex ACP $Label marker, found $count."
    }
    return $Text.Replace($Needle, $Replacement)
}

if (-not $source.Contains($forkMarker)) {
$needle = @'
  async newSession(request) {
'@
$replacement = @'
  async forkSession(request) {
    const turnIndex = request._meta?.aionui?.turnIndex;
    if (!Number.isInteger(turnIndex) || turnIndex < 0) {
      throw RequestError.invalidParams(
        { _meta: request._meta },
        "AionUI session/fork requires a non-negative _meta.aionui.turnIndex"
      );
    }
    const historyResponse = await this.codexClient.threadRead({
      threadId: request.sessionId,
      includeTurns: true
    });
    const turn = historyResponse.thread.turns?.[turnIndex];
    if (!turn?.id) {
      throw RequestError.invalidParams(
        { sessionId: request.sessionId, turnIndex },
        "The requested Codex turn checkpoint does not exist"
      );
    }
    const response = await this.codexClient.threadFork({
      threadId: request.sessionId,
      lastTurnId: turn.id
    });
    return { sessionId: response.thread.id };
  }
  async newSession(request) {
'@
$source = Replace-ExactlyOnce $source $needle $replacement 'client newSession'

$needle = @'
          list: {},
          close: {},
'@
$replacement = @'
          list: {},
          fork: {},
          close: {},
'@
$source = Replace-ExactlyOnce $source $needle $replacement 'capabilities'

$needle = @'
  async listSessions(params) {
'@
$replacement = @'
  async forkSession(params) {
    logger.log("Forking session...", { sessionId: params.sessionId });
    if (this.activePrompts.has(params.sessionId)) {
      throw RequestError.invalidRequest(`Session ${params.sessionId} has an active prompt`);
    }
    await this.checkAuthorization();
    const response = await this.runWithProcessCheck(() => this.codexAcpClient.forkSession(params));
    logger.log("Session forked", {
      sourceSessionId: params.sessionId,
      sessionId: response.sessionId
    });
    return response;
  }
  async listSessions(params) {
'@
$source = Replace-ExactlyOnce $source $needle $replacement 'server listSessions'

$needle = @'
  async threadArchive(params) {
'@
$replacement = @'
  async threadFork(params) {
    return await this.sendRequest({ method: "thread/fork", params });
  }
  async threadArchive(params) {
'@
$source = Replace-ExactlyOnce $source $needle $replacement 'app-server threadArchive'

$needle = '.onRequest(methods.agent.session.delete, (ctx) => getAgent().deleteSession(ctx.params)).onRequest(methods.agent.session.resume,'
$replacement = '.onRequest(methods.agent.session.delete, (ctx) => getAgent().deleteSession(ctx.params)).onRequest(methods.agent.session.fork, (ctx) => getAgent().forkSession(ctx.params)).onRequest(methods.agent.session.resume,'
$source = Replace-ExactlyOnce $source $needle $replacement 'router'
$changed = $true
}

if ($source.Contains($steerMarker)) {
    if (($source.Split($steerMarker).Count - 1) -ne 1) {
        throw 'Managed Codex ACP steer patch is duplicated.'
    }
} else {
    $needle = @'
function isExtMethodRequest(request) {
  return request.method === "authentication/status" || request.method === "authentication/logout" || request.method === LEGACY_SET_SESSION_MODEL_METHOD;
}
'@
    $replacement = @'
function isExtMethodRequest(request) {
  return request.method === "authentication/status" || request.method === "authentication/logout" || request.method === LEGACY_SET_SESSION_MODEL_METHOD || request.method === "_aionui/session/steer";
}
'@
    $source = Replace-ExactlyOnce $source $needle $replacement 'extension method guard'

    $needle = @'
    switch (methodRequest.method) {
      case "authentication/status":
'@
    $replacement = @'
    switch (methodRequest.method) {
      case "_aionui/session/steer":
        return await this.steerSession(methodRequest.params);
      case "authentication/status":
'@
    $source = Replace-ExactlyOnce $source $needle $replacement 'extension method switch'

    $needle = @'
  async prompt(params, signal) {
'@
    $replacement = @'
  async steerSession(params) {
    if (!Array.isArray(params.prompt) || params.prompt.length === 0) {
      throw RequestError.invalidParams(params, "AionUI steer requires a non-empty ACP prompt");
    }
    const activePrompt = this.activePrompts.get(params.sessionId);
    if (!activePrompt) {
      throw RequestError.invalidRequest(`Session ${params.sessionId} has no active prompt`);
    }
    const sessionState = this.getSessionState(params.sessionId);
    const activeTurn = activePrompt.currentTurn;
    const initialTurnId = activeTurn?.turnId ?? await this.getInterruptibleTurnId(sessionState, "Steer");
    if (!initialTurnId || this.activePrompts.get(params.sessionId) !== activePrompt) {
      throw RequestError.invalidRequest(`Session ${params.sessionId} has no active turn`);
    }
    const input = buildPromptItems(params.prompt);
    const maxAttempts = 41;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      if (this.activePrompts.get(params.sessionId) !== activePrompt) {
        break;
      }
      const currentTurn = activePrompt.currentTurn;
      const turnId = currentTurn?.turnId ?? initialTurnId;
      const threadId = currentTurn?.threadId ?? params.sessionId;
      try {
        const response = await this.runWithProcessCheck(() => this.codexAcpClient.turnSteer({
          threadId,
          expectedTurnId: turnId,
          input
        }));
        logger.log("Active turn steered", {
          sessionId: params.sessionId,
          turnId: response.turnId,
          attempt
        });
        return { turnId: response.turnId };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const isActiveTurnRace = message === "no active turn to steer" || message.startsWith("expected active turn id `");
        if (!isActiveTurnRace) {
          throw err;
        }
        if (attempt === 1) {
          logger.log("Native turn steer raced active-turn registration; retrying", {
            sessionId: params.sessionId,
            turnId,
            error: message
          });
        }
        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
      }
    }
    throw RequestError.invalidRequest(
      { sessionId: params.sessionId, turnId: initialTurnId },
      "AIONUI_STEER_TURN_ENDED: the active response ended before guidance could be applied"
    );
  }
  async prompt(params, signal) {
'@
    $source = Replace-ExactlyOnce $source $needle $replacement 'server prompt'

    $needle = @'
  async turnInterrupt(params) {
    return await this.sendRequest({ method: "turn/interrupt", params });
  }
'@
    $replacement = @'
  async turnSteer(params) {
    return await this.sendRequest({ method: "turn/steer", params });
  }
  async turnInterrupt(params) {
    return await this.sendRequest({ method: "turn/interrupt", params });
  }
'@
    $source = Replace-ExactlyOnce $source $needle $replacement 'app-server turnInterrupt'

    $needle = @'
var legacySetSessionModelParamsParser = external_exports.object({
  sessionId: external_exports.string(),
  modelId: external_exports.string()
}).passthrough();
'@
    $replacement = @'
var legacySetSessionModelParamsParser = external_exports.object({
  sessionId: external_exports.string(),
  modelId: external_exports.string()
}).passthrough();
var steerExtensionParamsParser = external_exports.object({
  sessionId: external_exports.string(),
  prompt: external_exports.array(external_exports.object({
    type: external_exports.literal("text"),
    text: external_exports.string().min(1)
  }).passthrough()).min(1)
}).passthrough();
'@
    $source = Replace-ExactlyOnce $source $needle $replacement 'steer params parser'

    $needle = '.onRequest("authentication/logout", emptyExtensionParamsParser, (ctx) => getAgent().extMethod("authentication/logout", ctx.params)).onRequest(LEGACY_SET_SESSION_MODEL_METHOD,'
    $replacement = '.onRequest("authentication/logout", emptyExtensionParamsParser, (ctx) => getAgent().extMethod("authentication/logout", ctx.params)).onRequest("__aionui/session/steer", steerExtensionParamsParser, (ctx) => getAgent().extMethod("_aionui/session/steer", ctx.params)).onRequest("_aionui/session/steer", steerExtensionParamsParser, (ctx) => getAgent().extMethod("_aionui/session/steer", ctx.params)).onRequest(LEGACY_SET_SESSION_MODEL_METHOD,'
    $source = Replace-ExactlyOnce $source $needle $replacement 'steer router'
    $changed = $true
}

# Upgrade the first steer implementation, which tried to recover the native
# active-turn registration race by starting a second turn.  CodexAcpClient has
# no turnStart bridge, and starting a new turn would not preserve steer
# semantics even if it did.  Retry the native turn/steer request for a bounded
# registration window instead.
$steerRetryMarker = 'AIONUI_STEER_TURN_ENDED: the active response ended before guidance could be applied'
if ($source.Contains($steerMarker) -and -not $source.Contains($steerRetryMarker)) {
    $legacySteerBody = @'
    const activeTurn = activePrompt.currentTurn;
    const turnId = activeTurn?.turnId ?? await this.getInterruptibleTurnId(sessionState, "Steer");
    if (!turnId || this.activePrompts.get(params.sessionId) !== activePrompt) {
      throw RequestError.invalidRequest(`Session ${params.sessionId} has no active turn`);
    }
    const threadId = activeTurn?.threadId ?? params.sessionId;
    const input = buildPromptItems(params.prompt);
    try {
      const response = await this.runWithProcessCheck(() => this.codexAcpClient.turnSteer({
        threadId,
        expectedTurnId: turnId,
        input
      }));
      logger.log("Active turn steered", { sessionId: params.sessionId, turnId: response.turnId });
      return { turnId: response.turnId };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const isActiveTurnRace = message === "no active turn to steer" || message.startsWith("expected active turn id `");
      if (!isActiveTurnRace || this.activePrompts.get(params.sessionId) !== activePrompt) {
        throw err;
      }
      logger.log("Native turn steer raced active-turn state; retrying as direct input", {
        sessionId: params.sessionId,
        turnId,
        error: message
      });
      const response = await this.runWithProcessCheck(() => this.codexAcpClient.turnStart({ threadId, input }));
      logger.log("Active turn steered through direct input", {
        sessionId: params.sessionId,
        turnId: response.turn.id
      });
      return { turnId: response.turn.id };
    }
'@
    $retrySteerBody = @'
    const activeTurn = activePrompt.currentTurn;
    const initialTurnId = activeTurn?.turnId ?? await this.getInterruptibleTurnId(sessionState, "Steer");
    if (!initialTurnId || this.activePrompts.get(params.sessionId) !== activePrompt) {
      throw RequestError.invalidRequest(`Session ${params.sessionId} has no active turn`);
    }
    const input = buildPromptItems(params.prompt);
    const maxAttempts = 41;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      if (this.activePrompts.get(params.sessionId) !== activePrompt) {
        break;
      }
      const currentTurn = activePrompt.currentTurn;
      const turnId = currentTurn?.turnId ?? initialTurnId;
      const threadId = currentTurn?.threadId ?? params.sessionId;
      try {
        const response = await this.runWithProcessCheck(() => this.codexAcpClient.turnSteer({
          threadId,
          expectedTurnId: turnId,
          input
        }));
        logger.log("Active turn steered", {
          sessionId: params.sessionId,
          turnId: response.turnId,
          attempt
        });
        return { turnId: response.turnId };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const isActiveTurnRace = message === "no active turn to steer" || message.startsWith("expected active turn id `");
        if (!isActiveTurnRace) {
          throw err;
        }
        if (attempt === 1) {
          logger.log("Native turn steer raced active-turn registration; retrying", {
            sessionId: params.sessionId,
            turnId,
            error: message
          });
        }
        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
      }
    }
    throw RequestError.invalidRequest(
      { sessionId: params.sessionId, turnId: initialTurnId },
      "AIONUI_STEER_TURN_ENDED: the active response ended before guidance could be applied"
    );
'@
    $source = Replace-ExactlyOnce $source $legacySteerBody $retrySteerBody 'legacy direct-input steer body'
    $changed = $true
}
if (($source.Split($steerRetryMarker).Count - 1) -ne 1) {
    throw 'Managed Codex ACP must contain exactly one bounded native-steer retry marker.'
}
if ($source.Contains('this.codexAcpClient.turnStart({ threadId, input })')) {
    throw 'Managed Codex ACP still contains the invalid direct-input steer fallback.'
}

# ACP extension methods gain one protocol-level underscore on the wire.  Older
# AionCore builds sent the legacy single-underscore spelling, so retain both
# routes while always dispatching the canonical method to the implementation.
$wireSteerRoute = '.onRequest("__aionui/session/steer", steerExtensionParamsParser, (ctx) => getAgent().extMethod("_aionui/session/steer", ctx.params))'
if ($source.Contains($wireSteerRoute)) {
    if (($source.Split($wireSteerRoute).Count - 1) -ne 1) {
        throw 'Managed Codex ACP wire steer route is duplicated.'
    }
} else {
    $legacySteerRoute = '.onRequest("_aionui/session/steer", steerExtensionParamsParser, (ctx) => getAgent().extMethod("_aionui/session/steer", ctx.params))'
    $source = Replace-ExactlyOnce $source $legacySteerRoute ($wireSteerRoute + $legacySteerRoute) 'wire steer route'
    $changed = $true
}

# The server owns a CodexAcpClient wrapper rather than the raw app-server
# client.  Keep an explicit forwarding method in that wrapper; adding only the
# lower-level turn/steer request compiles as JavaScript but fails at runtime
# with `this.codexAcpClient.turnSteer is not a function`.
$steerClientBridge = @'
  async turnSteer(params) {
    return await this.codexClient.turnSteer(params);
  }
'@
$steerClientBridgeCount = $source.Split($steerClientBridge).Count - 1
if ($steerClientBridgeCount -eq 0) {
    $needle = @'
  async turnInterrupt(params) {
    await this.codexClient.turnInterrupt({
'@
    $replacement = $steerClientBridge + "`n" + @'
  async turnInterrupt(params) {
    await this.codexClient.turnInterrupt({
'@
    $source = Replace-ExactlyOnce $source $needle $replacement 'CodexAcpClient turnInterrupt bridge'
    $changed = $true
} elseif ($steerClientBridgeCount -ne 1) {
    throw "Managed Codex ACP turnSteer client bridge is duplicated ($steerClientBridgeCount copies)."
}

$appServerSteer = @'
  async turnSteer(params) {
    return await this.sendRequest({ method: "turn/steer", params });
  }
'@
if (($source.Split($appServerSteer).Count - 1) -ne 1) {
    throw 'Managed Codex ACP must contain exactly one app-server turnSteer request method.'
}
if (($source.Split($steerClientBridge).Count - 1) -ne 1) {
    throw 'Managed Codex ACP must contain exactly one CodexAcpClient turnSteer bridge.'
}

if ($changed) {
    [IO.File]::WriteAllText($indexPath, $source, [Text.UTF8Encoding]::new($false))
}
