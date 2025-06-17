#pragma once

#include "BaseCode.h"


namespace oscuCrypto{

    template <typename T>
    class ComposedCode : public oc::BaseCode<T> {
        std::unique_ptr<oc::BaseCode<T>> first;
        std::unique_ptr<oc::BaseCode<T>> second;

    public:
        ComposedCode(std::unique_ptr<oc::BaseCode<T>> first, std::unique_ptr<oc::BaseCode<T>> second)
            : first(std::move(first)), second(std::move(second)) {}

        void invoke(const std::vector<T>& input, std::vector<T>& output) override {
            std::vector<T> intermediate;
            first->invoke(input, intermediate);
            second->invoke(intermediate, output);
        }
    };
}