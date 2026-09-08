local Fence = {}
Fence.__index = Fence

function Fence.new(node)
    assert(node, "node required")
    return setmetatable({ node = node }, Fence)
end

function Fence:highest()
    return self.node:term(), self.node.leader_id
end

function Fence:claim(claimant)
    assert(type(claimant) == "string", "claimant must be a string")
    if not self.node:is_leader() then
        return nil, "not the raft controller"
    end
    return self.node:term()
end

function Fence:observe(epoch, claimant)
    if type(epoch) ~= "number" or epoch < 1 or epoch % 1 ~= 0 then
        return nil, "bad controller epoch"
    end
    local term, leader = self.node:term(), self.node.leader_id
    if epoch == term and (leader == nil or claimant == nil or claimant == leader) then
        return true
    end
    return nil, string.format(
        "controller epoch %d does not match raft term %d (leader %s)",
        epoch, term, tostring(leader))
end

return Fence
