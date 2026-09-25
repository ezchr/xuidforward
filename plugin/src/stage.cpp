#include "stage.h"

namespace xuidforward {

IdentityStage &identity_stage()
{
    static IdentityStage stage;
    return stage;
}

}  // namespace xuidforward
